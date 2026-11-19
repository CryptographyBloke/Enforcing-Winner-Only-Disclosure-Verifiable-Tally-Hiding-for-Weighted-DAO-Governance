# Experiment output

Fresh experiments are written under this directory using unique run IDs. The `public/` subdirectory contains public inputs, replay outputs, measurements, and hashes. The sibling `private/oracle/` directory contains plaintext test vectors and must not be published. `logs/` stores per-stage command output.

All generated run directories and summaries are ignored by Git. Share only an export created after successful public replay and oracle comparison:

```powershell
node scripts/export_public_run.js --run runs\<run-id>\public --out runs\exports\<run-id>
```
