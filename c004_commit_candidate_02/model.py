"""Finite integer clock/error/delay exploration; not a physical timing guarantee."""
import argparse,itertools,json
from pathlib import Path
def run(p):
    with p.open('w',encoding='utf-8',newline='\n') as f:
        for g,d,delta,eps in itertools.product(range(5),range(9),range(4),range(3)):
            for error,gap in itertools.product(range(-eps,eps+1),range(9)):
                c=g+error+gap;sample=g<d;margin=g+delta+eps<d
                x=dict(g=g,d=d,delta=delta,eps=eps,error=error,gap=gap,c=c,sample_admit=sample,margin_admit=margin,
                    delay_bound_met=gap<=delta,margin_late=margin and c>=d,sample_late=sample and c>=d)
                f.write(json.dumps(x,sort_keys=True,separators=(',',':'))+'\n')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--result',type=Path,required=True);run(p.parse_args().result)
