"""Encrypted backup / restore CLI (SR-23).

    python tools/backup_restore.py backup
    python tools/backup_restore.py restore data/backups/evote-backup-....bin restored_data/
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app import create_app                                   # noqa: E402
from app.security.backup import create_backup, restore_backup  # noqa: E402


def main():
    app = create_app()
    svc = app.evote
    if len(sys.argv) >= 2 and sys.argv[1] == "backup":
        path = create_backup(svc.dbs, svc.keys, svc.dbs.data_dir / "backups")
        svc.audit.record("backup.created", "cli", "admin", {"file": path.name})
        print("Encrypted backup:", path)
    elif len(sys.argv) >= 4 and sys.argv[1] == "restore":
        files = restore_backup(svc.keys, Path(sys.argv[2]), Path(sys.argv[3]))
        svc.audit.record("backup.restored", "cli", "admin", {"file": Path(sys.argv[2]).name})
        print("Restored:", ", ".join(files), "->", sys.argv[3])
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
