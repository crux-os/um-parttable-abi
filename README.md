# um-parttable-abi

Crux OS partition-table service IPC protocol -- shared between
um-parttable and every client that needs to find its own partition
(e.g. um-cfs) without parsing GPT/MBR itself. Extracted from
um-parttable into its own repository so consumers depend on the
stable protocol contract, never on partition-table parsing internals.

Protocol v2: the `parttable` service over channels, a session per
client; `PartTable` is the client. Anyone may list partitions; changing a
disk (`mkgpt`, `add_partition`) takes a handle of that disk opened for
writing, which the service writes through. Also: `CRUXFS_TYPE_GUID`,
`ESP_TYPE_GUID`.
