import { emptyCounts, findConditionedKey, mergeCounts, secondByteZeroCount, wilsonInterval } from '../rc4/bias';
import { byteBlock, card, clear, details, el, field, scroller, verdict } from './dom';
import { drawPermutation } from './permutation';
export const BIAS_NEGATIVE_CLAIM = 'Passing every RFC 6229 vector does not make RC4 a sound cipher: the same verified implementation shows its second byte is zero about twice as often as chance.';

export function renderBiasCard(panel: HTMLElement): HTMLElement {
  const size=el('select',{id:'bias-size'},[12,14,16,18].map(power=>el('option',{value:String(2**power),selected:power===16,text:`2^${power} = ${(2**power).toLocaleString()} keys`})));
  const measure=el('button',{id:'bias-measure',type:'button',class:'btn btn-primary',text:'Measure second-byte bias'});
  const cancel=el('button',{id:'bias-cancel',type:'button',class:'btn',text:'Cancel measurement',disabled:true});
  const find=el('button',{id:'bias-find',type:'button',class:'btn',text:'Find a key with S₀[2] = 0'});
  const step=el('button',{id:'bias-step',type:'button',class:'btn',text:'Replay two PRGA rounds',disabled:true});
  const progress=el('p',{id:'bias-progress',role:'status','aria-live':'polite'});
  const output=el('div',{id:'bias-result','aria-live':'polite'});
  const keyOut=el('div',{id:'bias-key','aria-live':'polite'});
  const permutation=el('div',{id:'bias-permutation',class:'perm-wrap',role:'region',tabindex:'0','aria-label':'Conditioned RC4 permutation, 256 bytes',hidden:true});
  const traceOut=el('p',{id:'bias-trace','aria-live':'polite'});
  let running=false,stop=false,epoch=0,lastSize=size.value;
  let found:ReturnType<typeof findConditionedKey>|undefined, frame=0;
  const root=card([
    el('h3',{text:'The cipher on its own: the second byte leans toward zero'}),
    el('p',{text:'A good stream cipher’s bytes should look equally likely to be any of 256 values. RC4’s second byte is zero about twice as often as it should be. Count it yourself, then replay the two moves inside RC4 that cause it.'}),
    el('div',{class:'controls'},[field('Fresh 16-byte keys to sample',size),measure,cancel]),progress,output,
    el('h4',{text:'Why the second output can be forced to zero'}),
    el('p',{text:'If the initial permutation has S₀[2] = 0 and S₀[1] = X ≠ 2, the first swap places X at index X. The next round swaps zero into that same index and reads it out. These are actual PRGA frames, not a scripted illustration.'}),
    el('div',{class:'controls'},[find,step]),keyOut,permutation,traceOut,
    el('p',{id:'bias-negative',text:BIAS_NEGATIVE_CLAIM}),
    el('p',{},[
      document.createTextNode('This bias distinguishes RC4 from random. '),
      el('a',{href:'https://www.iacr.org/cryptodb/data/paper.php?pubkey=3134',text:'Mantin and Shamir (FSE 2001)'}),
      document.createTextNode(' used it to attack repeated plaintext encrypted under many keys. '),
      el('a',{href:'https://www.usenix.org/conference/usenixsecurity13/technical-sessions/paper/alfardan',text:'AlFardan and colleagues (USENIX 2013)'}),
      document.createTextNode(' later recovered plaintext from RC4 in TLS using further biases. '),
      el('a',{href:'https://www.rfc-editor.org/rfc/rfc7465.html',text:'RFC 7465'}),
      document.createTextNode(' prohibits RC4 cipher suites. This card measures a distinguishing bias; it does not execute those broadcast or TLS plaintext-recovery attacks.'),
    ]),
  ],{id:'rc4-bias'});
  function render(result:ReturnType<typeof emptyCounts>,partial:boolean,elapsed:number,goal:number) {
    clear(output);
    const baseline=1/256,interval=wilsonInterval(result.zero,result.n),control=wilsonInterval(result.controlZero,result.n);
    const excludes=interval[1]<baseline || interval[0]>baseline;
    const prefix=partial?`PARTIAL (${result.n} of ${goal} samples) — `:'';
    output.append(verdict(excludes?'alarm':'neutral',prefix+(excludes?'BIASED: second byte differs from uniform':`NOT YET DISTINGUISHABLE at n = ${result.n}`),{'data-claim':'bias-verdict'}));
    const rows=el('dl',{class:'count-list'});
    for(const [name,k,ci] of [['RC4',result.zero,interval],['Control',result.controlZero,control]] as const){
      const rate=result.n?k/result.n:0;
      rows.append(el('div',{class:'count-row',id:`bias-${name.toLowerCase()}-count`},[
        el('dt',{text:name}),el('dd',{text:`${k} / ${result.n}; rate ${rate.toFixed(8)}; ${(rate*256).toFixed(4)} × (1/256); 95% Wilson [${ci[0].toFixed(8)}, ${ci[1].toFixed(8)}]`}),
      ]));
    }
    output.append(rows,verdict('neutral',control[0]<=baseline&&control[1]>=baseline?'CONTROL: consistent with 1/256':'CONTROL: 1/256 lies outside this 95% interval; occasional exclusions occur by chance',{'data-claim':'bias-control'}));
    const rest=result.n-result.conditioned,restZero=result.zero-result.conditionedZero;
    output.append(el('p',{id:'bias-split',text:`Condition S₀[2] = 0 and S₀[1] ≠ 2: ${result.conditionedZero} / ${result.conditioned} gave Z₂ = 0. Other keys: ${restZero} / ${rest} gave Z₂ = 0.`}));
    output.append(verdict(result.failureKey?'fail':result.conditioned?'alarm':'neutral',result.failureKey?`CONDITION FAILED for key ${result.failureKey}`:result.conditioned?'EVERY KEY MEETING THE CONDITION GAVE Z₂ = 0':'No conditioned key was observed in this sample',{'data-claim':'bias-condition'}));
    const histogram=el('div',{class:'bias-histogram',role:'img','aria-label':`Second-byte histogram; bin 0 is striped and contains ${result.zero} of ${result.n} samples.`});
    const max=Math.max(1,...result.bins);
    result.bins.forEach((count,bin)=>histogram.append(el('div',{class:bin===0?'bias-bar bias-zero':'bias-bar',style:`height:${100*count/max}%`,title:`Byte ${bin}: ${count}`})));
    output.append(el('p',{class:'hint',text:'All 256 byte values, in order. Bin 0 is striped; exact counts are in the table.'}),scroller('RC4 second-byte histogram',[histogram],'bias-hist-scroll'));
    const table=el('table',{id:'bias-hist-table'},[
      el('caption',{text:'Second output byte of independently keyed RC4 streams'}),
      el('thead',{},[el('tr',{},[el('th',{text:'Byte value'}),el('th',{text:'Count'})])]),
      el('tbody',{},result.bins.map((count,bin)=>el('tr',{},[el('th',{scope:'row',text:String(bin)}),el('td',{text:String(count)})]))),
    ]);
    output.append(details('Inspect all 256 histogram counts',[scroller('RC4 second-byte counts by value',[table])]));
    output.append(el('p',{id:'bias-elapsed',text:`${result.n} samples in ${elapsed.toFixed(1)} ms. ${partial?'Cancelled; these are partial counts.':'Complete.'}`}));
  }
  measure.addEventListener('click',async()=>{
    const version=++epoch,goal=Number(size.value),start=performance.now();let result=emptyCounts();
    running=true;stop=false;clear(output);progress.textContent='Previous verdict retired. Drawing fresh keys and controls…';measure.disabled=true;cancel.disabled=false;
    try{
      while(result.n<goal && !stop && version===epoch){
        result=mergeCounts(result,secondByteZeroCount(Math.min(256,goal-result.n)));
        progress.textContent=`${result.n} of ${goal} samples measured.`;
        await new Promise<void>(resolve=>setTimeout(resolve,0));
      }
      if(version!==epoch)return;
      render(result,result.n<goal,performance.now()-start,goal);
      progress.textContent=result.n<goal?`Measurement stopped after ${result.n} samples; partial verdict below.`:`Completed ${result.n} fresh-key samples.`;
    }catch(error){if(version===epoch){clear(output);progress.textContent=(error as Error).message;}}
    finally{if(version===epoch){running=false;measure.disabled=false;cancel.disabled=true;}}
  });
  cancel.addEventListener('click',()=>{stop=true;});
  new MutationObserver(()=>{if(panel.hidden&&running)stop=true;}).observe(panel,{attributes:true,attributeFilter:['hidden']});
  size.addEventListener('change',()=>{
    if(size.value===lastSize)return;lastSize=size.value;epoch++;stop=true;running=false;clear(output);measure.disabled=false;cancel.disabled=true;progress.textContent='Sample size changed: previous verdict retired.';
  });
  find.addEventListener('click',()=>{
    clear(keyOut);clear(permutation);traceOut.textContent='';step.disabled=true;permutation.hidden=true;find.disabled=true;
    try{
      found=findConditionedKey();frame=0;
      if(!found.key){keyOut.textContent=`No conditioned key found in ${found.tries} tries. Try again; no state was fabricated.`;return;}
      keyOut.append(byteBlock('Conditioned 16-byte key',found.key),el('p',{id:'bias-found',text:`Found after ${found.tries} tries. S₀[2] = ${found.s0[2]}; S₀[1] = ${found.s0[1]} ≠ 2.`}));
      drawPermutation(permutation,found.s0,{i:2,j:1});permutation.hidden=false;step.disabled=false;step.textContent='Replay PRGA round 1';
    }catch(error){keyOut.textContent=(error as Error).message;}finally{find.disabled=false;}
  });
  step.addEventListener('click',()=>{
    if(!found?.trace||frame>=2)return;
    const current=found.trace[frame++];drawPermutation(permutation,current.s,{i:current.i,j:current.j,out:current.outIndex});
    traceOut.textContent=`Round ${frame}: i=${current.i}; j=${current.j}; S[i]=${current.sAtI}; S[j]=${current.sAtJ}; output index=${current.outIndex}; output byte=${current.out}.`;
    if(frame===2){keyOut.append(verdict(current.out===0?'alarm':'fail',current.out===0?'SECOND OUTPUT IS ZERO':'CONDITION FAILED: second output is not zero',{'data-claim':'bias-trace-verdict'}));step.disabled=true;step.textContent='Both rounds replayed';}
    else step.textContent='Replay PRGA round 2';
  });
  return root;
}
