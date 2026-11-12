"""Separate arithmetic oracle: full coverage, exact boundary and proof assumptions."""
import argparse,copy,json
from pathlib import Path
def need(x,s):
    if not x:raise ValueError(s)
def one(x):
    g,d,b,e,err,gap=(x[k] for k in ('g','d','delta','eps','error','gap'))
    need(all(type(v) is int for v in (g,d,b,e,err,gap)) and 0<=g<5 and 0<=d<9 and 0<=b<4 and 0<=e<3 and -e<=err<=e and 0<=gap<9,'MODEL_DOMAIN')
    need(x['c']==sum((g,err,gap)) and x['sample_admit']==(d-g>0) and x['margin_admit']==(d-g-b-e>0),'MODEL_ARITHMETIC')
    need(x['delay_bound_met']==(b-gap>=0) and x['margin_late']==(x['margin_admit'] and x['c']>=d) and x['sample_late']==(x['sample_admit'] and x['c']>=d),'MODEL_CLASSIFICATION')
    if x['margin_admit'] and x['delay_bound_met']:need(x['c']<=g+e+b<d,'CONDITIONAL_SUFFICIENT_BOUND')
    return tuple(x[k] for k in ('g','d','delta','eps','error','gap'))
def run(a):
    seen=set();counts=dict(rows=0,bounded_margin_admissions=0,bounded_margin_violations=0,unbounded_margin_counterexamples=0,sample_counterexamples=0,equality_boundary_refusals=0);mutants=0
    for line in a.input.read_text(encoding='utf-8').splitlines():
        x=json.loads(line);key=one(x);need(key not in seen,'NO_DUPLICATE_MODEL_ROW');seen.add(key);counts['rows']+=1
        counts['bounded_margin_admissions']+=int(x['margin_admit'] and x['delay_bound_met']);counts['bounded_margin_violations']+=int(x['margin_late'] and x['delay_bound_met'])
        counts['unbounded_margin_counterexamples']+=int(x['margin_late'] and not x['delay_bound_met']);counts['sample_counterexamples']+=int(x['sample_late'])
        counts['equality_boundary_refusals']+=int(x['g']+x['delta']+x['eps']==x['d'] and not x['margin_admit'])
        if counts['rows']<=8:
            for k in ('c','margin_admit','delay_bound_met'):
                b=copy.deepcopy(x);b[k]=not b[k] if type(b[k]) is bool else b[k]+1;need(b!=x,'MUTANT_CHANGED')
                try:one(b)
                except Exception:mutants+=1
                else:raise ValueError('BAD_MODEL_ROW_ACCEPTED')
    # Domain has5*9*4*(1+3+5)*9 distinct points; membership+cardinality proves finite coverage.
    need(len(seen)==14580 and counts['bounded_margin_admissions']>0 and counts['bounded_margin_violations']==0 and counts['unbounded_margin_counterexamples']>0 and counts['equality_boundary_refusals']>0 and mutants==24,'COMPLETE_NONVACUOUS_MODEL')
    r=dict(status='CONDITIONAL_MARGIN_MODEL_RECEIVED',**counts,mutations_rejected=mutants,physical_bound_proven=False,C004_closed=False)
    a.result.write_bytes((json.dumps(r,sort_keys=True,indent=2)+'\n').encode());print(json.dumps(r))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--input',type=Path,required=True);p.add_argument('--result',type=Path,required=True);run(p.parse_args())
