# 1.0.6 (May 29, 2019)

### Fixes

* Fixed output of print requests for primary keys

# 1.0.5 (May 24, 2019)

### Changes

* Merged two transactions into one in the place where the old index is replaced with a new index and there is a need to keep the original index name

# 1.0.4 (May 22, 2019)

### Fixes

* Fixed output of print requests for self-reindexation when it was not possible to do it automatically due to a long lock

# 1.0.3 (December 26, 2018)

### Fixes

* Fixed processing mixed case relation names by using quote_ident where applicable (Phil Krylov)
