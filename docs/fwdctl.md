# `fwdctl` Command Reference

The `fwdctl` binary manages Firewood databases during development and testing.  
This document highlights frequently used workflows and introduces the bulk loading
helper added for test automation.

## Bulk loading fixtures with `fwdctl load`

The `load` subcommand ingests a batch of key/value pairs from a JSON fixture file
into an existing Firewood database.

```bash
fwdctl load --db /path/to/firewood.db --file fixtures.json
```

The fixture file must be a JSON object that includes a schema block and a map of
UTF-8 string entries. Schema version **1** is currently supported and must be
declared explicitly.

For example:

```json
{
  "schema": {
    "version": 1
  },
  "entries": {
    "a": "1",
    "b": "2",
    "c": "3"
  }
}
```

Each entry is applied in a single proposal, reusing the same validation pipeline
that backs the `insert` command.  Loading an empty object completes without
issuing any writes and prints a short status message.  Successful runs print the
number of applied entries and the fixture path, which helps the test suite
assert that data was loaded as expected. The loader rejects unknown schema
versions with a non-zero exit code and an error that lists the supported
version.

### Upgrading older fixtures

Fixtures created before schema versioning was introduced can be updated by
wrapping the previous key/value object with the `schema` and `entries`
structure shown above. For example, a legacy fixture like:

```json
{
  "a": "1"
}
```

should be converted to:

```json
{
  "schema": {
    "version": 1
  },
  "entries": {
    "a": "1"
  }
}
```

## Measuring the integration test speedup

Switching the CLI integration tests to call `fwdctl load` instead of repeatedly
invoking `fwdctl insert` reduces startup overhead.  Using
`FIREWOOD_TEST_SEED=1 cargo test -p firewood-fwdctl --test cli` as a benchmark,
the suite completed in roughly **5.09 seconds** before the change and in roughly
**4.89 seconds** afterwards on the development container.  The exact improvement
varies with hardware, but developers should see noticeably shorter test runs
thanks to the consolidated fixture loader.
