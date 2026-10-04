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
import fcntl
parent=root.parent;parent.mkdir(parents=True,exist_ok=True,mode=0o700)
def private(path,directory=False):
 s=path.lstat()
 if path.is_symlink() or s.st_uid!=0 or s.st_mode & 0o777!=0o700 or (directory and not path.is_dir()) or (not directory and not path.is_file()): raise RuntimeError('unsafe reservation file: '+str(path))
# A preexisting root-owned parent may come from install -d (default 0755).
parent_fd=os.open(parent,os.O_DIRECTORY|os.O_NOFOLLOW)
if os.fstat(parent_fd).st_uid!=0: os.close(parent_fd);raise RuntimeError('unsafe reservation parent owner')
os.fchmod(parent_fd,0o700);os.close(parent_fd)
private(parent,True)
mutex_path=parent/(service+'.mutex')
fd=os.open(mutex_path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o700);os.close(fd);private(mutex_path)
mutex=mutex_path.open('a');fcntl.flock(mutex,fcntl.LOCK_EX)
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
 if probe_root.exists():
  if not remove: raise RuntimeError('owned probe cleanup not verified')
  import shutil
  shutil.rmtree(probe_root)
 if probe_root.exists(): raise RuntimeError('owned probe cleanup not verified')
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
mode=sys.argv[1]
if mode=='arm':
 if root.exists(): raise RuntimeError('reservation already exists')
 if owner.exists(): raise RuntimeError('another worker reservation exists')
 for unit in (service,timer):
  data=state(unit)
  if data.get('LoadState')!='loaded' or data.get('ActiveState') not in ('active','inactive') or data.get('UnitFileState') not in ('enabled','disabled','static'): raise RuntimeError('unsupported original unit state')
 if service not in state(timer).get('Triggers','').split(): raise RuntimeError('timer target mismatch')
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
probe.mkdir(mode=0o700)
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
 shutil.rmtree(probe)
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
 if result.returncode: raise RuntimeError('probe failed')
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
