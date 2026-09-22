# um-parttable-abi

Crux OS partition-table service IPC protocol -- shared between
um-parttable and every client that needs to find its own partition
(e.g. um-cfs) without parsing GPT/MBR itself. Extracted from
um-parttable into its own repository so consumers depend on the
stable protocol contract, never on partition-table parsing internals.
