# Implementing IronTrellis from the text

This page is for people who want to build their own checker for IronTrellis histories, or test their own system against ours, without reading our code. That kind of independent reading is the most useful review a specification can get.

## The rule

Work from the Internet-Draft and the vectors only:
- **Draft:** draft-rampertab-audit-agent-authority-history (IETF AUDIT discussion, audit@ietf.org).
- **Vectors:** the suites in this folder. [README.md](README.md) lists each suite, its counts, and what it covers.

Don't read the reference implementation first. If you need to, note where you did, so we know which part of the text wasn't enough.

## Keep an ambiguity log

As you read, write down every place where the text left you a choice: the section, the choice, and what you picked. That log is more useful to us than a pass count. Each entry becomes a fix in the next revision of the draft, with credit to you.

Send it as a GitHub issue using the **Spec ambiguity** template. One issue per ambiguity is easiest to track, but a single log is fine too.

## Run the vectors

Each vector gives an input history and the expected result. A checker passes a vector when it returns that result. Vectors that must be refused name the refusal code, and a checker passes only if it refuses for that reason.

```sh
node conformance/run.mjs --suite v1 -- <your checker command>    # any command after -- is run as the adapter
```

The runner talks to an adapter over a line protocol. [README.md](README.md#adapters) describes it and the runner's options, so your checker can be in any language.

## Contributing vectors

We welcome vectors from other implementations. Open a pull request, or an issue linking to your vector, with:
- the exact bytes (or a script that produces them deterministically);
- the expected result, and the section of the draft it relies on.

We agree on the bytes and the expected result with you before a vector is added, and we keep your credit and license notice. If you send code or vectors, you're credited in the commit (Co-authored-by) as well as in [ACKNOWLEDGMENTS.md](../ACKNOWLEDGMENTS.md).

## Security issues

If a vector shows that a checker accepts something it should refuse, report it privately as [SECURITY.md](../SECURITY.md) describes, not as a public issue.
