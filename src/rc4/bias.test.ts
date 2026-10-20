import { expect, it } from 'vitest';
import { emptyCounts, findConditionedKey, meetsKlCondition, mergeCounts, secondByteZeroCount, secureBytes, wilsonInterval } from './bias';
import { ksa, Rc4Keystream } from './rc4';

it('the second-byte conditioned property holds for every found key',()=>{
  const result=secondByteZeroCount(4096);
  expect(result.conditionedZero).toBe(result.conditioned);
  expect(result.failureKey).toBeUndefined();
  // No statistical lower bound on how many conditioned keys happen to be found.
  // The separate search below explicitly exercises a witness, without inventing one.
  const found=findConditionedKey(secureBytes,10000);
  if(found.key){expect(meetsKlCondition(ksa(found.key))).toBe(true);expect(new Rc4Keystream(found.key).next(2)[1]).toBe(0);}
  else expect(found.tries).toBe(10000);
});
it('fresh-key RC4 second-byte bias has a wide statistical separation from the control',()=>{
  const n=65536,result=secondByteZeroCount(n),interval=wilsonInterval(result.zero,n);
  expect(result.bins.reduce((a,b)=>a+b,0)).toBe(n);expect(result.bins[0]).toBe(result.zero);
  expect(result.zero*256/n).toBeGreaterThan(1.5);expect(result.zero*256/n).toBeLessThan(2.5);
  expect(interval[0]).toBeGreaterThan(1/256);
  expect(result.controlZero*256/n).toBeGreaterThan(0.5);expect(result.controlZero*256/n).toBeLessThan(1.5);
  // Under iid keys and the approximation p=2/256, Chernoff bounds give <8e-7
  // combined probability outside the RC4 point-estimate bounds. This is a model
  // estimate, not an exact probability for the RC4 KSA distribution. Those bounds
  // already imply the Wilson lower endpoint exceeds 1/256 at this n.
  // Uniform control: Chernoff gives <8e-12 for its two broad bounds.
  // We deliberately do NOT require a 95% interval to contain the true parameter:
  // that assertion would fail about 5% of ordinary runs by design.
});
it('Wilson small-count cases agree with independently simplified expressions',()=>{
  expect(wilsonInterval(0,0)).toEqual([0,1]);
  // k=0 => upper z²/(n+z²); k=n is its reflection.
  const zz=1.96**2;
  expect(wilsonInterval(0,10)[1]).toBeCloseTo(zz/(10+zz),14);
  expect(wilsonInterval(10,10)[0]).toBeCloseTo(10/(10+zz),14);
  // k=n/2 => center exactly .5; margin z/(2*sqrt(n+z²)).
  const margin=1.96/(2*Math.sqrt(10+zz));
  expect(wilsonInterval(5,10)[0]).toBeCloseTo(.5-margin,14);
  expect(wilsonInterval(5,10)[1]).toBeCloseTo(.5+margin,14);
  expect(()=>wilsonInterval(11,10)).toThrow('Invalid');
});
it('search reports exhaustion, and chunk aggregation preserves every count',()=>{
  const key=new Uint8Array(16);expect(meetsKlCondition(ksa(key))).toBe(false);
  const found=findConditionedKey(()=>key,12);expect(found.key).toBeNull();expect(found.tries).toBe(12);
  const a=secondByteZeroCount(19,length=>new Uint8Array(length)),b=secondByteZeroCount(21,length=>new Uint8Array(length));
  expect(mergeCounts(a,b)).toEqual(secondByteZeroCount(40,length=>new Uint8Array(length)));
  expect(mergeCounts(emptyCounts(),a)).toEqual(a);
});
