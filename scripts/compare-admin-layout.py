#!/usr/bin/env python3
"""Compare geometry and typography captured from the same original/migrated pages."""
import argparse
import json
from pathlib import Path

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline',type=Path,required=True)
    parser.add_argument('--current',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    comparisons=[]
    for before_file in sorted(args.baseline.rglob('*.json')):
        if before_file.name.startswith('.') or before_file.name=='results.json':continue
        before=json.loads(before_file.read_text(encoding='utf-8'))
        if 'viewport' not in before:continue
        after_file=args.current/before_file.relative_to(args.baseline)
        after=json.loads(after_file.read_text(encoding='utf-8'))
        changes=[]
        for selector,old in before.items():
            current=after.get(selector)
            pairs=old.items() if isinstance(old,dict) else [(selector,old)]
            for key,value in pairs:
                actual=current.get(key) if isinstance(old,dict) and isinstance(current,dict) else current
                if isinstance(value,(int,float)) and isinstance(actual,(int,float)):
                    same=abs(value-actual)<=1
                else:same=value==actual
                if not same:changes.append({'selector':selector,'property':key,'before':value,'after':actual})
        comparisons.append({'state':before_file.stem,'changes':changes})
    if len(comparisons)!=12:raise SystemExit(f'Expected 12 matching state/viewport captures, got {len(comparisons)}')
    args.output.write_text(json.dumps(comparisons,indent=2)+'\n',encoding='utf-8')
    count=sum(len(item['changes']) for item in comparisons)
    print(f'{len(comparisons)} original/migrated captures; {count} geometry/typography differences above 1 px')
    if count:raise SystemExit(1)

if __name__=='__main__':main()
