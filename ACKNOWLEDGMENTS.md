# Acknowledgments

IronTrellis is shaped by people outside the project who took the time to read it, question it, and test it. Being listed here means their ideas or work informed the design. It does not mean they endorse IronTrellis.

## From the IETF AUDIT discussion

- **Lars Kersten Kroehl** (MolTrust): refusals as first-class records with distinct causes.
- **Cliff Singletary**: the root grantor who loses standing without a recorded revocation, and the idea that actions in that gap stay valid at the time but are marked exposed.
- **Darren Wright** (Sencor): separating when an ending took effect from when it was recorded; a code distinct from revocation; the first outside test vector for IronTrellis.
- **Laurent Lemonnier** (iSoluce): the key-state model and INDETERMINATE when order can't be established; that the checker's policy, not the history, decides whose endings to accept; enforcing exposure before an action runs; and independent runs of IronTrellis vectors.

Each entry links to the change it drove in [CHANGELOG.md](CHANGELOG.md) once that change ships.

## How to be listed

Send an idea that changes the design, a vector, an ambiguity report, or code. See [CONTRIBUTING.md](CONTRIBUTING.md) and [conformance/IMPLEMENTERS.md](conformance/IMPLEMENTERS.md).
