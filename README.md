# G-Suite Community Drive Driver

## About

This driver was created for the Mozilla IAM Project to satisfy an OKR around community members accessing content
in GSuite.  

## Behavior

1. Spin up on cron/event trigger.
2. Scan the dynamodb table of all profiles.
3. Build a group data structure from all profiles.
4. Create a TeamDrive object from the library.
5. Opportunistically create team drive.
6. Reconcile the permissions list with the group membership based e-mail preferring Mozilla.org, then verified Google accounts.
7. Return a proposal per drive of add / remove / noops.
8. Execute the proposal for each set of ops.
9. Finish
