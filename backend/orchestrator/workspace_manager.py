"""Creates isolated baseline/candidate workspaces and freezes verified candidate snapshots."""
import shutil
from pathlib import Path
from backend.project_config.frozen import freeze
from backend.orchestrator.hashing import copy_tree,snapshot,files
from backend.integrations.git_adapter import git,init_repo

class WorkspaceManager:
    def __init__(self,root):self.root=Path(root).resolve();self.root.mkdir(parents=True,exist_ok=True)
    def create(self,run,source,candidate_source=None,require_config=False):
        # Keep an immutable baseline copy and a separate Git worktree for candidate changes.
        # `candidate_source` (gate runs) replaces the candidate's files with the head commit's.
        if source is None:raise ValueError('A source directory is required')
        home=self.root/run.run_id;home.mkdir(parents=True)
        base=copy_tree(source,home/'baseline')
        # Never inherit hooks, Git config, credentials, or symlinks from an external repository.
        commit=init_repo(base)
        candidate=home/'candidate'
        git(base,'worktree','add','-b','candidate-'+run.run_id,str(candidate),commit)
        if candidate_source is not None:
            for p in files(candidate):(candidate/p).unlink()
            copy_tree(candidate_source,candidate)
        # The base .asent/ (never part of a snapshot) is frozen beside the baseline as the run's authority.
        config=freeze(source,home,require_config)
        if config is not None:run.config_digest=config.digest;run.config_source=str(Path(source)/'.asent');run.config_problems=list(config.problems)
        run.baseline_commit=commit;run.baseline_workspace=str(base);run.candidate_workspace=str(candidate)
        return candidate
    def freeze(self,run):
        # Copy first, then compare hashes so analysis uses one stable candidate revision.
        dest=self.root/run.run_id/('snapshot-'+str(run.revision))
        copy_tree(run.candidate_workspace,dest)
        frozen=snapshot(dest)
        if frozen!=snapshot(run.candidate_workspace):raise RuntimeError('Candidate changed while snapshot was captured')
        return dest,frozen
    def reconstruct(self,run):
        # Rebuild an accepted workspace only if its bytes still match the verified snapshot.
        source=Path(run.candidate_workspace)
        if snapshot(source)!=run.candidate_snapshot:raise RuntimeError('Candidate changed after verification; cannot reconstruct')
        dest=self.root/run.run_id/('trusted-'+str(run.revision))
        git(self.root/run.run_id,'clone','--no-hardlinks',run.baseline_workspace,str(dest))
        for p in files(dest):(dest/p).unlink()
        copy_tree(source,dest)
        if snapshot(dest)!=run.candidate_snapshot:raise RuntimeError('Reconstruction digest mismatch')
        git(dest,'config','user.name','ASENT Local');git(dest,'config','user.email','asent@localhost')
        git(dest,'add','--all');git(dest,'commit','--allow-empty','-m','ASENT accepted '+run.run_id+' revision '+str(run.revision))
        run.clean_workspace=str(dest);run.clean_commit=git(dest,'rev-parse','HEAD')
        return run.clean_commit
