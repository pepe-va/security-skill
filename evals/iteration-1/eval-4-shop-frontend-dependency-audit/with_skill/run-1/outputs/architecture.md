# Architecture summary: shop-frontend (dependency audit)

1. **Product and principals.** A folder named shop-frontend whose package.json calls the project fixture-app. No
   application source is present, so users, operators and protected resources are not visible. Assumed: a public
   e-commerce frontend. The principals that matter for this audit are package publishers and registry operators
   (lower trust) and the developer machines, CI runners and application processes that install and run their code
   (higher trust).
2. **Comparable baseline.** None is source-grounded; omitted.
3. **Stack.** npm, lockfileVersion 3. Three direct dependencies, all exact pins: lodash 4.17.15 (registry.npmjs.org,
   sha512 integrity), expresss 4.18.2 (registry.npmjs.org, no integrity), colour-utilz 1.0.0 (packages.example.internal,
   no integrity). node_modules holds only colour-utilz. No build, test or CI configuration.
4. **Entry surfaces.** package.json:1 (declarations), package-lock.json:4-6 (resolution), and the colour-utilz
   postinstall hook (node_modules/colour-utilz/package.json:1 runs setup.js on install).
5. **Trust boundaries and controls.** Registry to install: exact pins plus a lockfile; integrity hashes only for lodash.
   Install to execution: no source-visible control over dependency install scripts. Library to application:
   unknown, because no application code is present.
6. **Starting paths.** package.json, package-lock.json, node_modules/colour-utilz/.
7. **Prior coverage.** No prior runs.
8. **Companions.** references/audit/dependencies.md (mode 3 procedure) and
   upstream/SUPPLY-CHAIN-AND-RELEASE.md: Core discipline, Dependency source and namespace confusion, Mutable and
   unbound build inputs, Universal moves, Validation rules. CI, release and codegen classes are excluded: no such
   surfaces in the target.
