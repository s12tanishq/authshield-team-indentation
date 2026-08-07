"""Local maintainer workflow for AuthShield pending reports.

Usage: python moderate.py list | approve <id> [--name "Portal"] | reject <id>
"""
import argparse
import database

parser = argparse.ArgumentParser()
sub = parser.add_subparsers(dest="command", required=True)
sub.add_parser("list")
approve_parser = sub.add_parser("approve")
approve_parser.add_argument("report_id", type=int)
approve_parser.add_argument("--name")
reject_parser = sub.add_parser("reject")
reject_parser.add_argument("report_id", type=int)
args = parser.parse_args()

if args.command == "list":
    for report in database.list_pending_reports():
        print(f"[{report['id']}] {report['report_type'].upper()} {report['domain']} ({report['created_at']})")
elif args.command == "reject":
    if database.get_pending_report(args.report_id) is None:
        raise SystemExit("Pending report not found.")
    database.mark_report_reviewed(args.report_id, "rejected")
    print(f"Rejected report {args.report_id}.")
else:
    report = database.get_pending_report(args.report_id)
    if report is None:
        raise SystemExit("Pending report not found.")
    if report["report_type"] == "trusted":
        if not database.insert_portal(report["domain"], report["dom_hash"], args.name or report["domain"], report["feature_signature"]):
            raise SystemExit("Could not approve: domain already exists or write failed.")
    else:
        database.insert_phishing_signature(report["dom_hash"], f"Maintainer-approved report for {report['domain']}")
    database.mark_report_reviewed(args.report_id, "approved")
    print(f"Approved report {args.report_id}.")
