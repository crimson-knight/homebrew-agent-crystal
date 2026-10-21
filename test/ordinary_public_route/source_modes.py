"""Admit exact Git executable classes through finite owned permission profiles."""
import os
import stat
from route_support import need

POLICY='git-executable-owned-permission-profiles-v110'
HISTORICAL_POLICY='exact-posix-modes-v108'
DEFAULT_POLICY=POLICY
PROFILES={
    '100644':{'022':0o644,'002':0o664,'077':0o600},
    '100755':{'022':0o755,'002':0o775,'077':0o700},
}

def physical_identity(value):
    return (value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)

def observe(info,git_mode):
    need(DEFAULT_POLICY in (POLICY,HISTORICAL_POLICY),'Exact reviewed source permission policy required')
    need(git_mode in PROFILES,'Exact regular Git executable class required')
    mode=stat.S_IMODE(info.st_mode);expected=PROFILES[git_mode]['022']
    if DEFAULT_POLICY==HISTORICAL_POLICY:return {'policy':DEFAULT_POLICY,'accepted':mode==expected,'working_tree_mode':mode,'expected_git_mode':git_mode,'profile':None,'refusals':[] if mode==expected else ['exact-historical-mode']}
    refusals=[];profile=next((name for name,value in PROFILES[git_mode].items() if value==mode),None)
    if not stat.S_ISREG(info.st_mode):refusals.append('regular-file-kind')
    if info.st_uid!=os.getuid():refusals.append('current-user-ownership')
    if info.st_nlink!=1:refusals.append('single-owned-file-link')
    if profile is None:refusals.append('exact-permission-profile-and-Git-executable-class')
    groups=sorted(set([os.getgid(),*os.getgroups()]))
    if mode&0o020 and info.st_gid not in groups:refusals.append('current-user-group-membership-for-group-write')
    return {'policy':POLICY,'accepted':not refusals,'working_tree_mode':mode,'expected_git_mode':git_mode,'profile':profile,'profile_meaning':'Compatible permission profile; actual historical umask causality remains unproved','owner_uid':info.st_uid,'group_gid':info.st_gid,'current_uid':os.getuid(),'current_groups':groups,'link_count':info.st_nlink,'refusals':refusals}
