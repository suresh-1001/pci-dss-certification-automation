
#!/usr/bin/env python3
import argparse, json, os, glob, csv
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    files = sorted(glob.glob(os.path.join(args.input, "evidence_*.json")))
    merged = []
    for fp in files:
        with open(fp, "r", encoding="utf-8") as f: merged.append(json.load(f))
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output + ".json","w",encoding="utf-8") as f: json.dump(merged, f, indent=2)
    out_csv = args.output + "_users.csv"
    with open(out_csv,"w",newline="",encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["host","control","user","enabled","password_required"])
        for rec in merged:
            host = rec.get("meta",{}).get("host",""); ctrl = rec.get("meta",{}).get("control","")
            for u in rec.get("localUsers",[]):
                w.writerow([host,ctrl,u.get("Name") or u.get("name",""),u.get("Enabled",""),u.get("PasswordRequired","")])
    print("Wrote", args.output + ".json"); print("Wrote", out_csv)
if __name__=="__main__": main()
