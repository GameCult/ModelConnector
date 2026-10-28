# ModelConnector

Status: planned. Nothing is implemented in this repository yet.

## What it will hold

The connector kit for GameCult minds:

- the connector contract, a Rust crate defining the typed boundary every model
  turn of a GameCult mind goes through;
- connector daemons that implement the contract against a model provider,
  Claude first, then an OpenAI-compatible connector.

The problem it solves: a mind should reach any model through one inspectable,
typed contract, rather than each project wiring its own provider calls.

## Where it comes from

[CodexConnector](https://github.com/GameCult/CodexConnector)
(GameCult/CodexConnector) is the existing connector this kit is lifted from.
The lift is the first piece of work here; until it lands there are no entry
points to run.

## License

AGPL-3.0-only. See `LICENSE`.
