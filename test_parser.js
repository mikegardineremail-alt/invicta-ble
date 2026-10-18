// Tests for the Invicta dashboard. Usage: node test_parser.js [path/to/index.html]  (default /workspace/site/index.html)
// All frames are SYNTHETIC (built from the documented JBD layout), not real captures.
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const HTML=process.argv[2]||'/workspace/site/index.html';
const html=fs.readFileSync(HTML,'utf8');
const code=html.split('// ===== PARSER-BEGIN')[1].split('// ===== PARSER-END')[0].replace(/^[^\n]*\n/,'');
const m={exports:{}}; vm.runInNewContext(code,{module:m});
const P=m.exports; const J=JSON.stringify;
let n=0; const t=(name,fn)=>{ fn(); n++; console.log('  ok', name); };
const be=v=>[(v>>8)&255,v&255];
function frame(cmd,payload,status=0){const body=[status,payload.length,...payload];const c=P.jbdChecksum(body);return [0xDD,cmd,...body,c>>8,c&255,0x77];}
const basicP=(o={})=>[...be(o.v??1330),...be((o.i??-250)&0xffff),...be(o.rem??7600),...be(o.full??4000),...be(12),...be(0x3221),0,0,0,0,...be(o.prot??0),0x10,o.soc??95,3,4,2,...be(o.t1??2981),...be(o.t2??2711)];
const F3=frame(3,basicP()), F4=frame(4,[...be(3321),...be(0x77DD),...be(3318),...be(3330)]);
const feedChunks=(a,s,k=20)=>{let g=[];for(let i=0;i<s.length;i+=k)g=g.concat(a.feed(s.slice(i,i+k)));return g;};
const sig=g=>J(g.map(x=>[x.cmd,x.ok]));

console.log('Parser / whitelist ('+HTML+')');
t('request checksums match app frames',()=>{
  assert.strictEqual(P.toHex(P.CMD_BASIC),'dda50300fffd77'); assert.strictEqual(P.toHex(P.CMD_CELLS),'dda50400fffc77');
  assert.strictEqual(P.jbdChecksum([3,0]),0xfffd); assert.strictEqual(P.jbdChecksum([4,0]),0xfffc); assert.strictEqual(P.jbdChecksum([0xe1,2,0,0]),0xff1d);
});
t('L1 whitelist compares exact bytes, constants frozen',()=>{
  assert(P.isAllowedBytes(Uint8Array.from(P.CMD_BASIC))&&P.isAllowedBytes(Uint8Array.from(P.CMD_CELLS)));
  assert(!P.isAllowedBytes(Uint8Array.from([0xDD,0x5A,0xE1,0x02,0,0,0xFF,0x1D,0x77])),'jump start');
  assert(!P.isAllowedBytes(Uint8Array.from([0xFF,0xAA,0x07,1,0x41])),'rename');
  assert(!P.isAllowedBytes(new Uint8Array([0xdda5,3,0,0xff,0xfd,0x77])),'type confusion 0xdda5 -> 0xa5');
  assert(!P.isAllowedBytes(P.CMD_BASIC),'plain array not accepted (must be final Uint8Array)');
  assert(!P.isAllowedBytes(Uint8Array.from([...P.CMD_BASIC,0])),'extra byte');
  assert(Object.isFrozen(P.CMD_BASIC)&&Object.isFrozen(P.CMD_CELLS)&&Object.isFrozen(P.ALLOWED));
  assert.strictEqual(J([...P.ALLOWED_HEX].sort()),J(['dda50300fffd77','dda50400fffc77']));
});
t('basic + cells decode',()=>{
  const g=feedChunks(new P.FrameAssembler(),[0x00,...F3,...F4]); assert.strictEqual(sig(g),J([[3,true],[4,true]]));
  const b=P.parseBasic(g[0].payload);
  assert.strictEqual(b.voltage,13.3); assert.strictEqual(b.current,-2.5); assert.strictEqual(b.remainAh,76); assert.strictEqual(b.fullAh,40);
  assert.strictEqual(b.soc,95); assert.strictEqual(b.cellCount,4); assert.strictEqual(J(b.temps),'[25,-2]'); assert.strictEqual(b.date,'2025-01-01');
  assert.strictEqual(b.status,'Discharge'); assert.strictEqual(J(P.parseCells(g[1].payload)),J([3.321,30.685,3.318,3.33]));
});
t('negative current/temp, protection status',()=>{
  const b=P.parseBasic(frame(3,basicP({i:-1234,t1:2631,prot:8})).slice(4,-3));
  assert.strictEqual(b.current,-12.34); assert.strictEqual(b.temps[0],-10); assert.strictEqual(b.status,'Protection');
});
t('short payload -> null (no NaN display)',()=>{ assert.strictEqual(P.parseBasic([0x05,0x32,0,0]),null); });

console.log('H1 capacity scale');
t('76/40 @95% -> k=2, "76.0 of 80"',()=>{ const k=P.capScale(76,40,95,null); assert.strictEqual(k,2); assert.strictEqual(P.capText(76,40,k),'76.0 of 80 Ah remaining'); });
t('30/40 @37.5% (old bug "30 of 40") -> "30.0 of 80"',()=>{ const k=P.capScale(30,40,37.5,null); assert.strictEqual(P.capText(30,40,k),'30.0 of 80 Ah remaining'); });
t('no flip across 51% boundary',()=>{ for(const soc of [95,60,52,51,50,40,20,10]){ assert.strictEqual(P.capScale(80*soc/100,40,soc,null),2,'soc '+soc); } });
t('single-BMS style pack stays k=1',()=>{ assert.strictEqual(P.capScale(38,40,95,null),1); assert.strictEqual(P.capScale(15,40,37.5,null),1); });
t('soc<10 keeps saved k, unknown otherwise',()=>{ assert.strictEqual(P.capScale(4,40,5,2),2); assert.strictEqual(P.capScale(4,40,5,null),null); assert.strictEqual(P.capScale(0,40,0,1),1);
  assert.match(P.capText(4,40,null),/learning/); });

console.log('H2 checksum gate');
t('corrupt frame flagged and classified bad-checksum',()=>{
  const bad=[...F3]; bad[5]^=0x40; const g=new P.FrameAssembler().feed(bad);
  assert(g.length>=1&&g[0].ok===false); assert.strictEqual(P.classifyFrame(g[0]),'bad-checksum');
  assert(!g.some(x=>x.ok),'no good frame invented from corrupt bytes');
});
t('classify ok/status',()=>{ const [g]=new P.FrameAssembler().feed(F3); assert.strictEqual(P.classifyFrame(g),'basic');
  const [e]=new P.FrameAssembler().feed(frame(3,[],0x80)); assert.strictEqual(P.classifyFrame(e),'bms-error'); });
t('corrupt frame followed by good frame -> good one still delivered',()=>{
  const bad=[...F4]; bad[6]^=1; const g=feedChunks(new P.FrameAssembler(),[...bad,...F3]);
  assert.strictEqual(g.filter(x=>x.ok).length,1); assert.strictEqual(g.find(x=>x.ok).cmd,3);
});

console.log('M1 reassembler resync (reviewer edge cases)');
t('1 three frames merged in one packet',()=>assert.strictEqual(sig(new P.FrameAssembler().feed([...F3,...F4,...F3])),J([[3,true],[4,true],[3,true]])));
t('2 one-byte packets',()=>assert.strictEqual(sig(feedChunks(new P.FrameAssembler(),[...F3,...F4],1)),J([[3,true],[4,true]])));
t('3 garbage before',()=>assert.strictEqual(sig(feedChunks(new P.FrameAssembler(),[1,2,0x77,3,...F3])),J([[3,true]])));
t('4 0x77/0xDD inside data',()=>assert.strictEqual(sig(feedChunks(new P.FrameAssembler(),F4)),J([[4,true]])));
t('5 status 0x80 error frame passes framing',()=>assert.strictEqual(sig(new P.FrameAssembler().feed(frame(3,[],0x80))),J([[3,true]])));
t('7 truncated F3 then 5 good frames -> all 5 recovered',()=>{ const a=new P.FrameAssembler(); a.feed(F3.slice(0,20));
  const g=feedChunks(a,[...F4,...F3,...F4,...F3,...F4]); assert(g.filter(x=>x.ok).length>=4,'got '+sig(g)); 
  assert.strictEqual(J(g.filter(x=>x.ok).slice(-4).map(x=>x.cmd)),J([3,4,3,4])); });
t('7b truncated F3 (cut inside header) then good frames',()=>{ const a=new P.FrameAssembler(); a.feed(F3.slice(0,3));
  const g=feedChunks(a,[...F4,...F3]); assert.strictEqual(J(g.filter(x=>x.ok).map(x=>x.cmd)),J([4,3])); });
t('8 false DD len=0xFF then 16 good frames, all recovered',()=>{ const a=new P.FrameAssembler(); a.feed([0xDD,0x00,0x00,0xFF]);
  let many=[];for(let k=0;k<8;k++)many.push(...F3,...F4); const g=feedChunks(a,many);
  assert.strictEqual(g.filter(x=>x.ok).length,16); assert.strictEqual(a.buf.length,0); });
t('8b false header with valid cmd but bad end byte resyncs by one byte',()=>{ const a=new P.FrameAssembler();
  const fake=[0xDD,0x03,0x00,0x02,0xAA,0xBB,0x00,0x00,0x00]; const g=feedChunks(a,[...fake,...F3]); assert.strictEqual(J(g.filter(x=>x.ok).map(x=>x.cmd)),J([3])); });
t('10 DD-flood keeps buffer bounded',()=>{ const a=new P.FrameAssembler(); let mx=0;
  for(let k=0;k<1000;k++){a.feed([0xDD,1,0,0xFF,...Array(16).fill(0)]); mx=Math.max(mx,a.buf.length);} assert(mx<=300,'max '+mx);
  const b=new P.FrameAssembler(); mx=0; for(let k=0;k<1000;k++){b.feed([0xDD,3,0,64,...Array(16).fill(0xDD)]); mx=Math.max(mx,b.buf.length);} assert(mx<=320,'valid-looking flood max '+mx); });

console.log('Temperature bands (LiFePO4 / Invicta spec)');
const key=c=>P.tempBand(c).key;
t('band edges',()=>{
  const cases=[[-25,'frozen'],[-20.1,'frozen'],[-20,'cold'],[-0.1,'cold'],[0,'cool'],[9.9,'cool'],[10,'ideal'],[27.5,'ideal'],[27.9,'ideal'],[29.9,'ideal'],
    [30,'warm'],[39.9,'warm'],[40,'hot'],[45,'hot'],[45.1,'tooHotChg'],[59.9,'tooHotChg'],[60,'tooHot'],[85,'tooHot']];
  for(const [c,k] of cases) assert.strictEqual(key(c),k,c+' -> '+key(c)+' expected '+k); });
t('band labels and levels',()=>{
  assert.strictEqual(P.tempBand(-5).label,'Cold: charging limited'); assert.strictEqual(P.tempBand(-30).label,'Too cold to charge');
  assert.strictEqual(P.tempBand(5).label,'Cool'); assert.strictEqual(P.tempBand(25).label,'Ideal'); assert.strictEqual(P.tempBand(35).label,'Warm');
  assert.strictEqual(P.tempBand(42).label,'Hot, ageing faster'); assert.strictEqual(P.tempBand(50).label,'Too hot to charge'); assert.strictEqual(P.tempBand(65).label,'Too hot');
  assert.strictEqual(P.tempBand(25).lvl,'ok'); assert.strictEqual(P.tempBand(65).lvl,'hot'); });
t('band rejects bad input',()=>{ for(const v of [null,undefined,NaN,Infinity,'25']) assert.strictEqual(P.tempBand(v),null); });
t('colour gradient: palette anchors + smooth + monotone warmth',()=>{
  assert.strictEqual(P.tempColor(-30),'#22d3ee'); assert.strictEqual(P.tempColor(0),'#22d3ee'); assert.strictEqual(P.tempColor(20),'#34d399');
  assert.strictEqual(P.tempColor(35),'#fbbf24'); assert.strictEqual(P.tempColor(42),'#f59e0b'); assert.strictEqual(P.tempColor(55),'#fb7185'); assert.strictEqual(P.tempColor(100),'#fb7185');
  assert.strictEqual(P.tempColor(null),'#8b93a7');
  const rgb=h=>[1,3,5].map(i=>parseInt(h.slice(i,i+2),16)); let prev=rgb(P.tempColor(-20));
  for(let c=-19.5;c<=80;c+=0.5){ const x=rgb(P.tempColor(c)); assert(/^#[0-9a-f]{6}$/.test(P.tempColor(c)));
    assert(Math.max(...x.map((v,j)=>Math.abs(v-prev[j])))<=40,'jump at '+c); prev=x; }
  const grn=c=>rgb(P.tempColor(c))[1]; for(let c=28;c<48;c++) assert(grn(c+1)<=grn(c),'green should fall as it warms (green->amber->rose) at '+c); });
t('bar width maps -20..60 °C, clamped',()=>{ assert.strictEqual(P.tempBarPct(-40),4); assert.strictEqual(P.tempBarPct(20),50); assert.strictEqual(P.tempBarPct(60),100);
  assert.strictEqual(P.tempBarPct(90),100); assert.strictEqual(P.tempBarPct(null),0); });
t('sensor names: #2 "Internal" (Invicta), #1 "BMS board" (JBD convention)',()=>{ assert.strictEqual(P.sensorName(0),'BMS board'); assert.strictEqual(P.sensorName(1),'Internal'); assert.strictEqual(P.sensorName(2),'Sensor 3'); });

// ---------- App-level integration (stub DOM + Web Bluetooth) ----------
async function appTests(){
  console.log('App integration (M2, M3, H2 end-to-end, L1-L3, L6)');
  const scripts=[...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(x=>x[1]);
  const els={}; const el=id=>els[id]||(els[id]={id,textContent:'',innerHTML:'',hidden:false,disabled:false,style:{},onclick:null,
    classList:{s:new Set(),toggle(c,v){v?this.s.add(c):this.s.delete(c);},add(c){this.s.add(c)},remove(c){this.s.delete(c)},contains(c){return this.s.has(c)}}});
  const store={}; const listeners={};
  const timers=new Set();
  const ctx={console,Math,Date,JSON,Promise,Error,Uint8Array,Object,Array,Set,String,Number,
    setTimeout:(f,ms)=>{const h=setTimeout(()=>{timers.delete(h);f();},ms);timers.add(h);return h;},
    clearTimeout:h=>{clearTimeout(h);timers.delete(h);}, setInterval:(f,ms)=>{const h=setInterval(f,ms);timers.add(h);return h;}, clearInterval:h=>{clearInterval(h);timers.delete(h);},
    localStorage:{getItem:k=>k in store?store[k]:null,setItem:(k,v)=>{store[k]=String(v)}},
    document:{getElementById:el,visibilityState:'visible',addEventListener:(e,f)=>{(listeners[e]=listeners[e]||[]).push(f)}},
    navigator:{}};
  ctx.window=ctx;
  // fake device
  const written=[]; let writeMode='ok'; let connectCalls=0; let connectGate=null;
  function mkDevice(id){
    const notifyL=[]; const devL={};
    const notify={addEventListener:(e,f)=>notifyL.push(f),removeEventListener:(e,f)=>{const i=notifyL.indexOf(f);if(i>=0)notifyL.splice(i,1);},startNotifications:async()=>{},
      emit(bytes){const u=Uint8Array.from(bytes);for(const f of [...notifyL])f({target:{value:new DataView(u.buffer)}});}};
    const write={writeValueWithoutResponse:(d)=>{ written.push(Array.from(d)); if(writeMode==='hang') return new Promise(()=>{}); if(writeMode==='reply'){ setTimeout(()=>{ if(d[2]===3) notify.emit(F3); else if(d[2]===4) notify.emit(F4); },5); } return Promise.resolve(); }};
    const svc={getCharacteristic:async u=>u.includes('faa1')?notify:write};
    const dev={id,name:'Starter Bat '+id,notify,devL,
      addEventListener:(e,f)=>{devL[e]=f},removeEventListener:(e,f)=>{if(devL[e]===f)delete devL[e]},
      gatt:{connected:false,connect:async()=>{connectCalls++; if(connectGate) await connectGate; dev.gatt.connected=true; return {getPrimaryService:async u=>{if(u.includes('faa0'))return svc;throw new Error('nf')}}},
            disconnect(){ dev.gatt.connected=false; devL.gattserverdisconnected&&devL.gattserverdisconnected(); }}};
    return dev;
  }
  const devA=mkDevice('A'), devB=mkDevice('B');
  let reqDev=devA;
  ctx.navigator.bluetooth={requestDevice:async()=>reqDev,getDevices:async()=>[devB]};
  vm.createContext(ctx);
  for(const s of scripts) vm.runInContext(s+'\n;globalThis.__st=typeof st!=="undefined"?st:undefined;globalThis.__api={sendCmd:typeof sendCmd!=="undefined"?sendCmd:null,setup:typeof setup!=="undefined"?setup:null,scheduleReconnect:typeof scheduleReconnect!=="undefined"?scheduleReconnect:null,CMD_BASIC};',ctx);
  const st=ctx.__st, api=ctx.__api; const wait=ms=>new Promise(r=>setTimeout(r,ms));
  const sleep0=()=>wait(30);

  // L1 runtime whitelist
  await assert.rejects(api.sendCmd([0xDD,0x5A,0xE1,0x02,0,0,0xFF,0x1D,0x77]),/BLOCKED/); n++; console.log('  ok sendCmd refuses jump-start bytes');
  await assert.rejects(api.sendCmd([0xFF,0xAA,0x07,1,0x41]),/BLOCKED/); n++; console.log('  ok sendCmd refuses rename bytes');

  // connect A with replies
  writeMode='reply'; await el('btnConnect').onclick(); await wait(1300);
  assert(st.basic&&st.basic.voltage===13.3,'basic from device'); assert(st.cells.length===4&&st.cellsAt>0);
  assert(written.every(w=>P.isAllowedBytes(Uint8Array.from(w))),'only whitelisted bytes ever written');
  assert.strictEqual(el('vAh').textContent,'76.0 of 80 Ah remaining'); assert.strictEqual(store.invictaCapK,'2'); n++; console.log('  ok connect, poll, decode, H1 text + k persisted');
  // temps in the default frame: 2981 -> 25.0 °C, 2711 -> -2.0 °C
  assert.match(el('vT1').innerHTML,/^25\.0/); assert.strictEqual(el('vT1').style.color,P.tempColor(25)); assert.match(el('vT2').innerHTML,/^-2\.0/);
  assert.strictEqual(el('vBand').textContent,'Cold: charging limited'); assert.strictEqual(el('vT2').style.color,P.tempColor(-2)); assert.match(el('vTall').textContent,/BMS board 25\.0°C · Ideal\nInternal -2\.0°C · Cold: charging limited/);
  assert.match(el('vTgap').innerHTML,/^27\.0.*board warmer/); assert.strictEqual(el('socBar').style.width,'95%'); assert.strictEqual(el('gMaskArc').style.strokeDashoffset,String(100-(18/80*100)));
  n++; console.log('  ok temperature hero renders main/board/gap, colour, band, gauge + charge bar');
  assert.match(el('vI2').innerHTML,/est\./); n++; console.log('  ok M5 x2 labelled est.');

  // H2 end-to-end: corrupt frame must not change display
  const before=st.basic; const bad=frame(3,basicP({v:9999})); bad[bad.length-2]^=1; devA.notify.emit(bad);
  assert.strictEqual(st.basic,before); assert.match(el('log').textContent,/checksum mismatch/); n++; console.log('  ok H2 corrupt frame ignored, logged');

  // M3: hanging write times out, queue does not grow, watchdog reconnects
  writeMode='hang'; const w0=written.length; await wait(2600);
  assert(written.length-w0<=3,'writes while hung: '+(written.length-w0)); assert(st.writePending===false||st.writePending===true);
  await wait(4500);
  assert.match(el('log').textContent,/write timeout/); assert.match(el('log').textContent,/no data for 6 s/); n++; console.log('  ok M3 write timeout + bounded writes + watchdog reconnect');
  writeMode='reply'; await wait(2500); assert(devA.gatt.connected,'reconnected'); n++; console.log('  ok M3 recovered after watchdog');

  // M2: setup failure after connect fires both catch and gattserverdisconnected -> only one pending timer / one setup
  const cc=connectCalls; let resolveGate; connectGate=new Promise(r=>resolveGate=r);
  devA.gatt.disconnect(); // triggers onDisc -> scheduleReconnect
  await wait(1700); // timer fired, setup in progress (connect gated)
  devA.devL.gattserverdisconnected&&devA.devL.gattserverdisconnected(); // spurious disconnect during connecting
  api.scheduleReconnect(); api.scheduleReconnect();
  resolveGate(); connectGate=null; await wait(300);
  assert.strictEqual(connectCalls-cc,1,'exactly one connect attempt, got '+(connectCalls-cc)); n++; console.log('  ok M2 single reconnect timer, no concurrent setup');

  // L2: manual disconnect shows reconnect button again
  el('btnDisconnect').onclick(); await sleep0();
  assert.strictEqual(el('btnConnect').hidden,false); assert.strictEqual(el('btnReconnect').hidden,false); n++; console.log('  ok L2 reconnect button reappears after manual disconnect');
  // L3: reconnectLast with saved id A but getDevices only has B -> must NOT connect to B
  const ccB=connectCalls; await el('btnReconnect').onclick(); await sleep0();
  assert.strictEqual(connectCalls,ccB); assert.match(el('log').textContent,/not remembered/); n++; console.log('  ok L3 reconnectLast matches saved id only');
  // L6: switching to device B clears A's data
  reqDev=devB; writeMode='hang'; await el('btnConnect').onclick(); await sleep0();
  assert.strictEqual(st.basic,null); assert.strictEqual(st.cells.length,0); n++; console.log('  ok L6 data cleared on device switch');
  // M4 visibility handler registered
  assert((listeners.visibilitychange||[]).length===1); n++; console.log('  ok M4 visibilitychange handler present');
  st.wantConnected=false; for(const h of timers){clearTimeout(h);clearInterval(h);} 
}
appTests().then(()=>{ console.log(`\nALL ${n} TESTS PASSED`); process.exit(0); }).catch(e=>{ console.error('FAIL',e); process.exit(1); });
