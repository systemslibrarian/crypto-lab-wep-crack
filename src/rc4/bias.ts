import { ksa, Rc4Keystream, type PrgaStep } from './rc4';
export type ByteSource = (length: number) => Uint8Array;
export const secureBytes: ByteSource = length => {
  if (!globalThis.crypto?.getRandomValues) throw new Error('crypto.getRandomValues is unavailable; no fallback random source is used.');
  return crypto.getRandomValues(new Uint8Array(length));
};
export function meetsKlCondition(s0: Uint8Array): boolean { return s0[2] === 0 && s0[1] !== 2; }
export function wilsonInterval(k: number, n: number, z = 1.96): [number,number] {
  if (!Number.isInteger(n) || n < 0 || !Number.isInteger(k) || k < 0 || k > n || z <= 0) throw new Error('Invalid binomial count or confidence parameter.');
  if (n === 0) return [0,1];
  const rate=k/n,zz=z*z,den=1+zz/n,center=(rate+zz/(2*n))/den;
  const margin=z*Math.sqrt(rate*(1-rate)/n+zz/(4*n*n))/den;
  return [Math.max(0,center-margin),Math.min(1,center+margin)];
}
export interface BiasCounts { n: number; zero: number; controlZero: number; bins: number[]; conditioned: number; conditionedZero: number; failureKey?: string }
export function emptyCounts(): BiasCounts { return {n:0,zero:0,controlZero:0,bins:Array(256).fill(0),conditioned:0,conditionedZero:0}; }
// [extension] point: a per-position scan would record the first 256 outputs.
export function secondByteZeroCount(n: number, keySource: ByteSource = secureBytes): BiasCounts {
  if (!Number.isInteger(n) || n < 0) throw new Error('Sample count must be a nonnegative integer.');
  const result=emptyCounts();
  for(let i=0;i<n;i++){
    // [extension] point: a WEP IV || shared-key source belongs in its own experiment.
    const key=keySource(16);if(key.length!==16)throw new Error('Expected a 16-byte sample key.');
    const initial=ksa(key), stream=new Rc4Keystream(key).next(2);
    const second=stream[1];
    result.bins[second]++;result.zero+=Number(second===0);
    const control=keySource(2);if(control.length!==2)throw new Error('Expected a 2-byte control sample.');
    result.controlZero+=Number(control[1]===0);result.n++;
    if(meetsKlCondition(initial)){
      result.conditioned++;result.conditionedZero+=Number(second===0);
      if(second!==0)result.failureKey=Array.from(key,b=>b.toString(16).padStart(2,'0')).join('');
    }
  }
  return result;
}
export function mergeCounts(a: BiasCounts,b: BiasCounts): BiasCounts {
  return {n:a.n+b.n,zero:a.zero+b.zero,controlZero:a.controlZero+b.controlZero,bins:a.bins.map((n,i)=>n+b.bins[i]),conditioned:a.conditioned+b.conditioned,conditionedZero:a.conditionedZero+b.conditionedZero,failureKey:a.failureKey??b.failureKey};
}
export function findConditionedKey(rng: ByteSource = secureBytes,maxTries=10000) {
  if(!Number.isInteger(maxTries)||maxTries<1)throw new Error('Try budget must be positive.');
  for(let tries=1;tries<=maxTries;tries++){
    const key=rng(16),s0=ksa(key);
    if(meetsKlCondition(s0)){
      const trace:PrgaStep[]=[];new Rc4Keystream(key).next(2,trace);
      return {tries,key,s0,trace};
    }
  }
  return {tries:maxTries,key:null,s0:null,trace:null};
}
