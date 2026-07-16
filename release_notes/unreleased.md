**Unreleased**

* Enabled TLS certificate verification by default for Firepower API connections.
* Limited network group discovery to 2,000 pages so an invalid FMC pagination stream cannot loop indefinitely.
* Preserved referenced network objects when block and unblock actions replace the Firepower network group.
* Used Firepower atomic group-member updates so concurrent containment actions no longer replace one another.
* Waited for Firepower deployment tasks to report success and surfaced failed, aborted, missing, or timed-out outcomes.
* Checked and deployed pending Firepower configuration even when a block or unblock request already matched the staged group.
