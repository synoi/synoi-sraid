import { createHash, generateKeyPairSync, sign as nsign, verify as nverify, randomBytes } from 'node:crypto'

function bench(name, fn, target=1000){
  let it=1
  for(;;){const t0=process.hrtime.bigint();for(let i=0;i<it;i++)fn();const dt=Number(process.hrtime.bigint()-t0)/1e6;if(dt>=50){it=Math.max(1,Math.floor(it*(target/dt)));break}it*=4}
  let best=Infinity
  for(let r=0;r<3;r++){const t0=process.hrtime.bigint();for(let i=0;i<it;i++)fn();const ns=Number(process.hrtime.bigint()-t0)/it;if(ns<best)best=ns}
  console.log(name.padEnd(32), (best.toFixed(1)+' ns/op').padStart(16), Math.round(1e9/best).toLocaleString('en-US').padStart(14)+' ops/sec')
}

const msg = randomBytes(985)
let s=0
bench('native SHA-256 (OpenSSL)', ()=>{ s+=createHash('sha256').update(msg).digest()[0] })

const { publicKey, privateKey } = generateKeyPairSync('ed25519')
const sig = nsign(null, msg, privateKey)
bench('native ed25519 verify', ()=>{ s+=nverify(null,msg,publicKey,sig)?1:0 })
bench('native ed25519 sign',   ()=>{ s+=nsign(null,msg,privateKey)[0] })
console.log('// sink', s)
