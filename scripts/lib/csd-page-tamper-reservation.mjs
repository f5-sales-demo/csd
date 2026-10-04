import { randomUUID } from 'node:crypto';

// Persistent systemd guard: no controller signal or shell finally is needed to restore.
export function reservationLifetime(timings) {
  return Math.ceil(
    (timings.bootstrapControlMs +
      timings.quietMs * 2 +
      timings.pollMs +
      timings.maximumCaseMs +
      timings.recoveryMs * 2 +
      timings.commandTimeoutMs * 12) /
      1000,
  );
}

// Recovery evidence is supplied by an independent verifier BEFORE recovery; never
// synthesize it from a blocked guard or a remembered instantaneous ActiveState.
// reservation is the exact original state.json snapshot, with phase='complete'.
// Its run_id/service/timer, Type/RemainAfterExit and durable dispatch states are
// checked against the rendered identity and real systemd on EVERY replay.
export const RESTORE_EVIDENCE_CONTRACT = Object.freeze({
  contract: 'xcsh-csd-restore-evidence-v1',
  missingStatePath: '<directory>/restore-evidence.json',
  completedCleanupPath: '/var/lib/xcsh-csd-reservation/<runId>.restore-evidence.json',
  required: ['contract', 'externally_verified', 'reservation'],
  completedCleanupRequired: ['cleanup_complete'],
  ownership: 'root-owned regular files and root-owned directories, mode 0700, no symlinks',
  dispatch:
    'original UnitFileState and timer ActiveState; service Type/RemainAfterExit and coherent timer-owned execution',
});

// Kept identical in the guard, worker cleanup and independent recovery helper.
export const WORKER_MUTEX_PROTOCOL = `import fcntl,stat
def canonical_directory(path,create=False):
 path=pathlib.Path(path)
 fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
 try:
  for part in path.parts[1:]:
   try: child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
   except FileNotFoundError:
    if not create or part!=path.name: raise
    os.mkdir(part,0o700,dir_fd=fd);os.fsync(fd)
    child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
   s=os.fstat(child)
   if s.st_uid!=0 or stat.S_IMODE(s.st_mode)&0o022: raise RuntimeError('unsafe mutex ancestor')
   os.close(fd);fd=child
  s=os.fstat(fd)
  if stat.S_IMODE(s.st_mode)!=0o700: raise RuntimeError('unsafe mutex parent')
  return fd
 except:
  os.close(fd);raise
def reservation_mutex(parent,service):
 parent_fd=canonical_directory(parent,True)
 name=service+'.mutex'
 try:
  try: fd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent_fd);os.fsync(parent_fd)
  except FileExistsError: fd=os.open(name,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent_fd)
  try:
   def checked():
    s=os.fstat(fd);p=os.stat(name,dir_fd=parent_fd,follow_symlinks=False)
    if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_nlink!=1 or s.st_size!=0 or stat.S_IMODE(s.st_mode) not in (0o600,0o644) or (s.st_dev,s.st_ino)!=(p.st_dev,p.st_ino): raise RuntimeError('unsafe reservation mutex')
    current=canonical_directory(parent)
    try:
     if (os.fstat(current).st_dev,os.fstat(current).st_ino)!=(os.fstat(parent_fd).st_dev,os.fstat(parent_fd).st_ino): raise RuntimeError('mutex parent replaced')
    finally: os.close(current)
    return s
   checked()
   fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
   if stat.S_IMODE(checked().st_mode)==0o644: os.fchmod(fd,0o600);os.fsync(fd)
   checked()
   return fd
  except: os.close(fd);raise
 finally: os.close(parent_fd)
`;

// Same-filesystem quarantine is private even when /tmp is a separate mount.
export const WORKER_FILESYSTEM_PROTOCOL = `import shutil,tempfile
def worker_authority(run):
 journal=pathlib.Path('/var/lib/xcsh-csd-recovery')/run/'lifecycle.json'
 os.close(canonical_directory(journal.parent.parent));os.close(canonical_directory(journal.parent))
 fd=os.open(journal,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  s=os.fstat(fd)
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o700: raise RuntimeError('worker authority unsafe')
  with os.fdopen(os.dup(fd)) as f: value=json.load(f)
 finally: os.close(fd)
 if value.get('contract')!='xcsh-csd-prearm-v1' or value.get('worker_identity',{}).get('runId')!=run or value.get('worker_identity',{}).get('root')!='/tmp/xcsh-csd-'+run: raise RuntimeError('worker authority mismatch')
 return journal,value
def worker_directory(run):
 journal,value=worker_authority(run);p=pathlib.Path('/tmp/xcsh-csd-'+run)
 fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);s=os.fstat(fd)
 if s.st_uid!=0 or stat.S_IMODE(s.st_mode)!=0o755 or value.get('root_inode')!=[s.st_dev,s.st_ino] or [p.lstat().st_dev,p.lstat().st_ino]!=[s.st_dev,s.st_ino]: os.close(fd);raise RuntimeError('worker root ownership unavailable')
 return fd
def worker_quarantine(run):
 journal,value=worker_authority(run);root=pathlib.Path('/tmp/xcsh-csd-'+run)
 parent_fd=os.open('/tmp',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  parent=os.fstat(parent_fd)
  if parent.st_uid!=0 or not parent.st_mode & stat.S_ISVTX: raise RuntimeError('unsafe worker parent')
  qname='.xcsh-csd-quarantine-'+run
  try: os.mkdir(qname,0o700,dir_fd=parent_fd);os.fsync(parent_fd)
  except FileExistsError: pass
  qfd=os.open(qname,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent_fd);q=os.fstat(qfd)
  try:
   if q.st_uid!=0 or stat.S_IMODE(q.st_mode)!=0o700: raise RuntimeError('unsafe worker quarantine')
   if value.get('quarantine_inode') not in (None,[q.st_dev,q.st_ino]): raise RuntimeError('worker quarantine replaced')
   if value.get('quarantine_inode') is None:
    if not os.path.lexists(root) and value.get('root_inode'): raise RuntimeError('worker disappeared without cleanup authority')
    value['quarantine_inode']=[q.st_dev,q.st_ino]
    fd,tmp=tempfile.mkstemp(prefix='.quarantine-',dir=journal.parent);os.fchmod(fd,0o700)
    with os.fdopen(fd,'w') as f: json.dump(value,f);f.flush();os.fsync(f.fileno())
    os.replace(tmp,journal);jfd=os.open(journal.parent,os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(jfd);os.close(jfd)
   def exists(name,fd):
    try: return os.stat(name,dir_fd=fd,follow_symlinks=False)
    except FileNotFoundError: return None
   source=exists(root.name,parent_fd);saved=exists('worker',qfd)
   if source and saved: raise RuntimeError('ambiguous worker cleanup roots')
   candidate=source or saved
   if candidate:
    import pwd
    try: worker_uid=pwd.getpwnam('ubuntu').pw_uid
    except KeyError: worker_uid=-1
    if not stat.S_ISDIR(candidate.st_mode) or candidate.st_uid not in (0,worker_uid) or stat.S_IMODE(candidate.st_mode) not in (0o700,0o755) or value.get('root_inode')!=[candidate.st_dev,candidate.st_ino]: raise RuntimeError('worker root ownership unavailable')
    if source: os.rename(root.name,'worker',src_dir_fd=parent_fd,dst_dir_fd=qfd);os.fsync(parent_fd);os.fsync(qfd)
    saved=exists('worker',qfd)
    if value.get('root_inode')!=[saved.st_dev,saved.st_ino]: raise RuntimeError('worker root replaced during cleanup')
    if not shutil.rmtree.avoids_symlink_attacks: raise RuntimeError('descriptor cleanup unavailable')
    value['cleanup_intent']=True
    fd,tmp=tempfile.mkstemp(prefix='.cleanup-',dir=journal.parent);os.fchmod(fd,0o700)
    with os.fdopen(fd,'w') as f: json.dump(value,f);f.flush();os.fsync(f.fileno())
    os.replace(tmp,journal);jfd=os.open(journal.parent,os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(jfd);os.close(jfd)
    shutil.rmtree('worker',dir_fd=qfd);os.fsync(qfd)
   elif value.get('root_inode') and not value.get('cleanup_intent'): raise RuntimeError('worker disappeared without cleanup intent')
   value['cleanup_intent']=True
   fd,tmp=tempfile.mkstemp(prefix='.cleanup-',dir=journal.parent);os.fchmod(fd,0o700)
   with os.fdopen(fd,'w') as f: json.dump(value,f);f.flush();os.fsync(f.fileno())
   os.replace(tmp,journal);jfd=os.open(journal.parent,os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(jfd);os.close(jfd)
  finally: os.close(qfd)
 finally: os.close(parent_fd)
`;

export function renderReservation({
  runId,
  lifetimeSeconds,
  service = 'csd-continuous.service',
  timer = 'csd-continuous.timer',
  fixture = false,
}) {
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(runId) ||
    !Number.isInteger(lifetimeSeconds) ||
    lifetimeSeconds < 1
  )
    throw new Error('invalid reservation identity');
  if (
    (!fixture && (service !== 'csd-continuous.service' || timer !== 'csd-continuous.timer')) ||
    !/^[a-z0-9-]+\.service$/.test(service) ||
    !/^[a-z0-9-]+\.timer$/.test(timer) ||
    (fixture && (!service.startsWith('xcsh-csd-fixture-') || !timer.startsWith('xcsh-csd-fixture-')))
  )
    throw new Error('invalid reservation targets');
  const name = `xcsh-csd-restore-${runId}`;
  const directory = `/var/lib/xcsh-csd-reservation/${runId}`;
  const script = `#!/usr/bin/python3
import json,os,pathlib,subprocess,sys,time
root=pathlib.Path(${JSON.stringify(directory)})
service=${JSON.stringify(service)}
timer=${JSON.stringify(timer)}
name=${JSON.stringify(name)}
run_id=${JSON.stringify(runId)}
lifetime=${lifetimeSeconds}
${WORKER_MUTEX_PROTOCOL}
${WORKER_FILESYSTEM_PROTOCOL}
parent=root.parent
mutex=reservation_mutex(parent,service)
def private(path,directory=False):
 s=path.lstat()
 if path.is_symlink() or s.st_uid!=0 or s.st_mode & 0o777!=0o700 or s.st_nlink!=1 and not directory or (directory and not path.is_dir()) or (not directory and not path.is_file()): raise RuntimeError('unsafe reservation file: '+str(path))
private(parent,True)
owner=parent/(service+'.owner')
def owned():
 private(root,True);private(root/'guard.py');private(owner)
 if owner.read_text()!=run_id: raise RuntimeError('reservation ownership mismatch')
def ctl(*args,check=True):
 p=subprocess.run(['systemctl',*args],capture_output=True,text=True)
 if check and p.returncode: raise RuntimeError('systemd operation failed: '+args[0]+' '+p.stderr.strip())
 return p.stdout.strip()
def state(unit):
 data=ctl('show',unit,'--property=LoadState,ActiveState,UnitFileState,Triggers,FragmentPath,Type,RemainAfterExit,ExecMainStartTimestampMonotonic,ExecMainStatus,Result')
 return dict(line.split('=',1) for line in data.splitlines() if '=' in line)
def save(value):
 tmp=root/'state.new'
 fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o700)
 with os.fdopen(fd,'w') as f: json.dump(value,f);f.flush();os.fsync(f.fileno())
 os.chmod(tmp,0o700);os.replace(tmp,root/'state.json')
 fd=os.open(root,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
def validate(value):
 if value.get('run_id')!=run_id or value.get('service')!=service or value.get('timer')!=timer: raise RuntimeError('restoration identity mismatch')
 for unit in (service,timer):
  original=value.get(unit,{})
  if original.get('ActiveState') not in ('active','inactive') or original.get('UnitFileState') not in ('enabled','disabled','static'): raise RuntimeError('invalid restoration snapshot')
 if not value[service].get('Type') or value[service].get('RemainAfterExit') not in ('yes','no') or service not in value[timer].get('Triggers','').split(): raise RuntimeError('invalid restoration dispatch policy')
 if value.get('phase') not in ('draining','prepared','service_intent','service_resumed','timer_intent','resumed','complete'): raise RuntimeError('invalid restoration phase')
def verify_dispatch(value):
 for unit in (service,timer):
  actual=state(unit);original=value[unit]
  if actual.get('LoadState')!='loaded' or actual.get('UnitFileState')!=original['UnitFileState']: raise RuntimeError('restoration durable state mismatch')
  if unit==timer:
   if actual['ActiveState']!=original['ActiveState'] or service not in actual.get('Triggers','').split(): raise RuntimeError('restoration timer mismatch')
  else:
   if any(actual.get(k)!=original.get(k) for k in ('Type','RemainAfterExit')): raise RuntimeError('restoration service policy mismatch')
   if value[timer]['ActiveState']=='active':
    allowed=('active','activating','inactive')
   elif original['ActiveState']=='active':
    allowed=('inactive',) if original['Type']=='oneshot' and original['RemainAfterExit']=='no' else ('active',)
   else: allowed=('inactive',)
   if actual['ActiveState'] not in allowed: raise RuntimeError('restoration service mismatch')
def verify_probe_cleanup(remove=False):
 probe_root=pathlib.Path('/tmp/xcsh-csd-'+run_id)
 for process in pathlib.Path('/proc').iterdir():
  if not process.name.isdecimal(): continue
  try: argv=(process/'cmdline').read_bytes().split(b'\\0')
  except FileNotFoundError: continue
  if any(arg.startswith(('--user-data-dir='+str(probe_root)+'/probe-').encode()) for arg in argv): raise RuntimeError('owned browser remains active')
 if os.path.lexists(probe_root):
  if not remove: raise RuntimeError('owned probe cleanup not verified')
  if ${fixture ? 'True' : 'False'} and not os.path.lexists(pathlib.Path('/var/lib/xcsh-csd-recovery')/run_id/'lifecycle.json'):
   # Fixture-only historical guard matrix never prepares a worker root.
   raise RuntimeError('fixture worker root lacks inode authority')
  worker_quarantine(run_id)
 if os.path.lexists(probe_root): raise RuntimeError('owned probe cleanup not verified')
def load():
 cleaned=not root.exists()
 if not cleaned:
  owned()
  path=root/'state.json'
  if path.exists():
   private(path);value=json.loads(path.read_text());validate(value);return value
 # Only PREEXISTING private external evidence authorizes absent-state recovery.
 # A completed-cleanup receipt lives outside the deleted run directory.
 path=parent/(run_id+'.restore-evidence.json') if cleaned else root/'restore-evidence.json'
 private(path);evidence=json.loads(path.read_text())
 if evidence.get('contract')!='xcsh-csd-restore-evidence-v1' or evidence.get('externally_verified') is not True: raise RuntimeError('missing authoritative restoration evidence')
 value=evidence.get('reservation',{});validate(value)
 if value['phase']!='complete': raise RuntimeError('restoration evidence is incomplete')
 verify_dispatch(value);verify_probe_cleanup()
 if cleaned:
  if evidence.get('cleanup_complete') is not True or owner.exists(): raise RuntimeError('cleanup ownership evidence mismatch')
  for suffix in ('service','timer'):
   if state(name+'.'+suffix).get('LoadState')!='not-found' or pathlib.Path('/etc/systemd/system/'+name+'.'+suffix).exists(): raise RuntimeError('guard cleanup evidence mismatch')
  if pathlib.Path('/run/systemd/system/'+name+'.timer.d').exists(): raise RuntimeError('guard override cleanup evidence mismatch')
  value['cleanup_evidence']=True
 else:
  actual=state(name+'.timer')
  if actual.get('LoadState')!='not-found' and (actual.get('ActiveState')!='inactive' or actual.get('UnitFileState')!='disabled'): raise RuntimeError('guard cleanup evidence mismatch')
 return value
def restore():
 value=load()
 if value.get('cleanup_evidence'):
  print('XCSH_RESULT '+json.dumps({'restored':True,'original_states_preserved':True}));return
 if value['phase']=='draining':
  units=ctl('list-units','--all','--plain','--no-legend','xcsh-csd-probe-'+run_id+'-*',check=False)
  for line in units.splitlines():
   unit=line.split()[0]
   if unit.startswith('xcsh-csd-probe-'+run_id+'-') and unit.endswith('.service'): ctl('stop',unit)
  ctl('stop',timer);ctl('stop',service)
  for unit in (timer,service):
   original=value[unit]
   if original['UnitFileState'] in ('enabled','disabled'): ctl('enable' if original['UnitFileState']=='enabled' else 'disable',unit)
  value['phase']='prepared';save(value)
 if value['phase']=='prepared':
  value['service_start_before']=state(service).get('ExecMainStartTimestampMonotonic')
  value['phase']='service_intent';save(value)
 if value['phase']=='service_intent':
  actual=state(service);original=value[service]
  for unit in (service,timer):
   observed=state(unit)
   if observed.get('LoadState')!='loaded' or observed.get('UnitFileState')!=value[unit]['UnitFileState']: raise RuntimeError('restoration durable state mismatch')
  if any(actual.get(k)!=original.get(k) for k in ('Type','RemainAfterExit')) or service not in state(timer).get('Triggers','').split(): raise RuntimeError('restoration service policy mismatch')
  if original['ActiveState']=='active':
   if actual['ActiveState']=='failed' or (actual['ActiveState']=='inactive' and actual.get('ExecMainStartTimestampMonotonic')==value['service_start_before']):
    ctl('start',service);actual=state(service)
   completed=original['Type']=='oneshot' and original['RemainAfterExit']=='no' and actual['ActiveState']=='inactive' and actual.get('ExecMainStartTimestampMonotonic')!=value['service_start_before'] and actual.get('Result')=='success' and actual.get('ExecMainStatus')=='0'
   if actual['ActiveState']!='active' and not completed: raise RuntimeError('restoration service start unverified')
  elif actual['ActiveState']!='inactive': raise RuntimeError('restoration service mismatch')
  value['phase']='service_resumed';save(value)
 if value['phase']=='service_resumed': value['phase']='timer_intent';save(value)
 if value['phase']=='timer_intent':
  if value[timer]['ActiveState']=='active' and state(timer)['ActiveState']!='active': ctl('start',timer)
  value['phase']='resumed';save(value)
 # No target stops/restarts after resume intent, including cleanup failures and crashes.
 verify_dispatch(value);verify_probe_cleanup(remove=True)
 if state(name+'.timer').get('LoadState')!='not-found':
  ctl('disable','--now',name+'.timer')
  if state(name+'.timer')['ActiveState']!='inactive' or state(name+'.timer')['UnitFileState']!='disabled': raise RuntimeError('guard not disarmed')
 value['phase']='complete';value['restored']=True;save(value)
 print('XCSH_RESULT '+json.dumps({'restored':True,'original_states_preserved':True}))
journal=pathlib.Path('/var/lib/xcsh-csd-recovery')/run_id/'lifecycle.json'
def arm_phase(phase,pause=False):
 if ${fixture ? 'True' : 'False'} and not os.path.lexists(journal): return
 os.close(canonical_directory(journal.parent.parent));os.close(canonical_directory(journal.parent))
 private(journal);authority=json.loads(journal.read_text())
 if authority.get('contract')!='xcsh-csd-prearm-v1' or authority.get('worker_identity',{}).get('runId')!=run_id or authority.get('worker_identity',{}).get('root')!='/tmp/xcsh-csd-'+run_id or authority.get('service')!=service or authority.get('timer')!=timer: raise RuntimeError('prearm authority mismatch')
 if phase=='ARM_INTENT' and (authority.get('phase')!='NOT_ARMED' or authority.get('pause_intent') is not False): raise RuntimeError('prearm authority consumed')
 authority['phase']=phase;authority['pause_intent']=pause
 import tempfile
 fd,temporary=tempfile.mkstemp(prefix='.arm-',dir=journal.parent);os.fchmod(fd,0o700)
 with os.fdopen(fd,'w') as out: json.dump(authority,out);out.flush();os.fsync(out.fileno())
 os.replace(temporary,journal)
 fd=os.open(journal.parent,os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
mode=sys.argv[1]
if mode=='arm':
 if root.exists(): raise RuntimeError('reservation already exists')
 if owner.exists(): raise RuntimeError('another worker reservation exists')
 for unit in (service,timer):
  data=state(unit)
  if data.get('LoadState')!='loaded' or data.get('ActiveState') not in ('active','inactive') or data.get('UnitFileState') not in ('enabled','disabled','static'): raise RuntimeError('unsupported original unit state')
 if service not in state(timer).get('Triggers','').split(): raise RuntimeError('timer target mismatch')
 arm_phase('ARM_INTENT')
 root.mkdir(parents=True,mode=0o700)
 value={unit:state(unit) for unit in (service,timer)}
 value.update(run_id=run_id,service=service,timer=timer,phase='draining',restored=False,expires_at=time.time()+lifetime);save(value)
 fd=os.open(owner,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o700)
 with os.fdopen(fd,'w') as f: f.write(run_id);f.flush();os.fsync(f.fileno())
 restore_unit='[Unit]\\nDescription=Owned CSD reservation restoration\\nAfter=network.target\\nStartLimitIntervalSec=0\\n[Service]\\nType=oneshot\\nExecStart=/usr/bin/python3 '+str(root/'guard.py')+' restore\\nRestart=on-failure\\nRestartSec=5s\\nTimeoutStartSec=180s\\n'
 timer_unit='[Unit]\\nDescription=Owned CSD reservation deadline and boot recovery\\n[Timer]\\nOnActiveSec='+str(lifetime)+'s\\nOnBootSec=1s\\nAccuracySec=1s\\nUnit='+name+'.service\\n[Install]\\nWantedBy=timers.target\\n'
 # OnBootSec would fire immediately on an already-running host. Arm with a runtime
 # override suppressing only boot trigger; the override disappears on reboot.
 for suffix,body in (('service',restore_unit),('timer',timer_unit)):
  pathlib.Path('/etc/systemd/system/'+name+'.'+suffix).write_text(body)
 override=pathlib.Path('/run/systemd/system/'+name+'.timer.d');override.mkdir(parents=True)
 (override/'boot.conf').write_text('[Timer]\\nOnBootSec=\\nOnActiveSec='+str(lifetime)+'s\\n')
 pathlib.Path(root/'guard.py').write_text(pathlib.Path(__file__).read_text());os.chmod(root/'guard.py',0o700)
 ctl('daemon-reload');ctl('enable','--now',name+'.timer')
 if state(name+'.timer')['ActiveState']!='active' or state(name+'.timer')['UnitFileState']!='enabled': raise RuntimeError('guard not armed')
 # No production stop before the independently managed guard has been verified.
 arm_phase('PAUSE_INTENT',True)
 ctl('disable','--now',timer)
 if value[service]['UnitFileState']=='enabled': ctl('disable',service)
 ctl('stop',service)
 if state(timer)['ActiveState']!='inactive' or state(service)['ActiveState']!='inactive': raise RuntimeError('dispatch not drained')
 print('XCSH_RESULT '+json.dumps({'armed':True,'dispatch_drained':True,'lifetime_seconds':lifetime}))
elif mode=='restore': restore()
elif mode=='verify':
 value=load()
 if value['phase']!='draining' or value.get('restored') or time.time()>=value['expires_at'] or state(name+'.timer')['ActiveState']!='active' or state(timer)['ActiveState']!='inactive' or state(service)['ActiveState']!='inactive': raise RuntimeError('reservation expired or lost')
 print('XCSH_RESULT '+json.dumps({'armed':True}))
elif mode=='cleanup':
 value=load()
 if not value.get('cleanup_evidence'):
  if value['phase']!='complete': raise RuntimeError('restoration not verified')
  verify_dispatch(value);verify_probe_cleanup()
  if state(name+'.service').get('LoadState')!='not-found': ctl('stop',name+'.service')
  if state(name+'.timer').get('LoadState')!='not-found': ctl('disable','--now',name+'.timer')
  import shutil
  for suffix in ('service','timer'): pathlib.Path('/etc/systemd/system/'+name+'.'+suffix).unlink(missing_ok=True)
  shutil.rmtree('/run/systemd/system/'+name+'.timer.d',ignore_errors=True)
  ctl('daemon-reload')
  for suffix in ('service','timer'):
   if state(name+'.'+suffix).get('LoadState')!='not-found': raise RuntimeError('guard cleanup not verified')
  verify_dispatch(value);verify_probe_cleanup();owned()
  owner.unlink();shutil.rmtree(root)
 print('XCSH_RESULT '+json.dumps({'cleaned':True,'restored':True,'original_states_preserved':True}))
else: raise RuntimeError('unknown reservation action')
`;
  return { name, directory, script };
}

export function renderHeadedProbe({ root, probeId = randomUUID(), entry, timeoutSeconds = 120 }) {
  if (!/^\/tmp\/xcsh-csd-[0-9a-f-]{36}$/.test(root) || !/^[0-9a-f-]{36}$/.test(probeId))
    throw new Error('invalid probe identity');
  return `#!/usr/bin/python3
import json,os,pathlib,shutil,signal,subprocess,sys,time
root=pathlib.Path(${JSON.stringify(root)})
probe=root/${JSON.stringify(`probe-${probeId}`)}
if not probe.is_dir() or probe.is_symlink() or probe.stat().st_uid!=os.getuid(): raise RuntimeError('owned probe workspace unavailable')
profile=probe/'profile';profile.mkdir(mode=0o700)
chrome=next((shutil.which(c) for c in ('/opt/chrome/chrome','google-chrome-stable','google-chrome','chromium') if shutil.which(c)),None)
node=shutil.which('/opt/node/bin/node') or shutil.which('node')
xvfb=shutil.which('Xvfb')
if not all((chrome,node,xvfb)): raise RuntimeError('headed runtime unavailable')
processes=[]
def cleanup():
 for p in reversed(processes):
  if p.poll() is None:
   os.killpg(p.pid,signal.SIGTERM)
   try: p.wait(timeout=5)
   except subprocess.TimeoutExpired: os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=5)
 for child in probe.iterdir():
  if child.is_dir() and not child.is_symlink(): shutil.rmtree(child)
  else: child.unlink()
def abort(signum,frame): raise RuntimeError('owned probe interrupted')
signal.signal(signal.SIGTERM,abort);signal.signal(signal.SIGINT,abort)
try:
 x=subprocess.Popen([xvfb,'-displayfd','1','-screen','0','1280x720x24','-nolisten','tcp'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True);processes.append(x)
 import select
 if not select.select([x.stdout],[],[],10)[0]: raise RuntimeError('display unavailable')
 display=':'+x.stdout.readline().decode().strip()
 if not display[1:].isdigit() or x.poll() is not None: raise RuntimeError('display invalid')
 env=dict(os.environ,DISPLAY=display)
 args=[chrome,'--enable-automation','--no-first-run','--no-default-browser-check','--remote-debugging-address=127.0.0.1','--remote-debugging-port=0','--user-data-dir='+str(profile),'about:blank']
 c=subprocess.Popen(args,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True);processes.append(c)
 deadline=time.monotonic()+30
 while not (profile/'DevToolsActivePort').exists():
  if time.monotonic()>deadline or c.poll() is not None: raise RuntimeError('Chrome unavailable')
  time.sleep(.1)
 port=(profile/'DevToolsActivePort').read_text().splitlines()[0]
 argv=pathlib.Path('/proc/'+str(c.pid)+'/cmdline').read_bytes().split(b'\\0')
 environment=pathlib.Path('/proc/'+str(c.pid)+'/environ').read_bytes().split(b'\\0')
 if any(a.startswith(b'--headless') for a in argv) or ('--user-data-dir='+str(profile)).encode() not in argv or ('DISPLAY='+display).encode() not in environment or x.poll() is not None: raise RuntimeError('headed process provenance invalid')
 (probe/'entry.mjs').write_text(${JSON.stringify(entry)})
 result=subprocess.run([node,str(probe/'entry.mjs')],env=dict(env,XCSH_PROBE_PORT=port),capture_output=True,text=True,timeout=${timeoutSeconds})
 if result.returncode:
  # Only the bounded exception summary is emitted, never captured source/stack lines.
  import re
  summaries=re.findall(r'^(?:[A-Za-z]+Error|Error): ([^\\r\\n]+)$',result.stderr,re.M)
  detail=summaries[-1] if summaries else 'entry exited '+str(result.returncode)
  detail=re.sub(r'https?://\\S+|data:\\S+|(?:APIToken|Bearer)\\s+\\S+','[redacted]',detail)
  detail=re.sub(r'(?i)(?:token|password|secret|cookie|authorization)[=: ]+[^,; ]+','[redacted]',detail)
  raise RuntimeError('probe entry failed: '+detail[:240])
 lines=[line for line in result.stdout.splitlines() if line.startswith('XCSH_RESULT ')]
 if len(lines)!=1: raise RuntimeError('probe evidence invalid')
 value=json.loads(lines[0][12:])
 evidence=value.pop('_browser_evidence',None)
 if not evidence or any(a.startswith('--headless') for a in evidence['arguments']) or '--user-data-dir='+str(profile) not in evidence['arguments'] or 'Headless' in evidence['product']: raise RuntimeError('browser provenance invalid')
 value['browser_provenance']={'mode':'headed-xvfb','placement':'worker','process_arguments_verified':True,'browser_arguments_verified':True,'owned_display_verified':True,'product':evidence['product']}
 print('XCSH_RESULT '+json.dumps(value))
finally: cleanup()
`;
}
