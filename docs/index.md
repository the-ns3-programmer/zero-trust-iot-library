# Zero Trust Module for IoT Devices in ns-3

This library brings Zero Trust principles — verify explicitly, enforce least
privilege, assume breach — into [ns-3](https://www.nsnam.org/) simulations of
constrained, distributed IoT networks. The modules cover identity, policy
enforcement, certificates, encryption, session security, continuous trust
re-evaluation, and observability, and they interoperate to form one coherent,
enforceable trust boundary around every node and every communication event.

- **[Model](model/index.md)** — the reusable Zero Trust engine: identity
  registry, policy engine, certificates, encryption/hash utilities, TLS-style
  handshake, context-drift revalidation, dynamic trust scoring, the IPv4
  enforcement hook, and the shared logger.
- **[Examples](examples/index.md)** — runnable ns-3 scratch programs, including
  three attack/mitigation pairs (MITM, spoofing, unauthorized access) and three
  standalone module tests.
- **[License](license.md)** — the project's GPLv2 license plus every
  third-party license bundled under `LICENSES/`.

## Getting started

1. Clone the ns-3 mainline code:

   ```bash
   git clone -b ns-3.45 https://gitlab.com/nsnam/ns-3-dev.git
   ```

2. Change into the `contrib` directory:

   ```bash
   cd contrib
   ```

3. Clone this module:

   ```bash
   git clone https://github.com/the-ns3-programmer/zero-trust-iot.git
   ```

4. Configure and build ns-3. Make sure [cryptopp](https://github.com/weidai11/cryptopp)
   is installed first:

   ```bash
   ./ns3 configure --enable-examples --enable-tests -- -DNS3_CRYPTOPP=ON
   ./ns3 build
   ```

5. Copy any example from [Examples](examples/index.md) into the `scratch/`
   folder and run it with `./ns3 run scratch/<name>`.

## Contributors

### Core Maintainers

| Name | Affiliation | Contact |
| :--- | :--- | :--- |
| **Arun Santhosh R A** | DevOps Engineer | [arunsanthosh.rashok@gmail.com](mailto:arunsanthosh.rashok@gmail.com) |
| **Dr. Subbulakshmi T** | Professor, VIT Chennai | [subbulakshmibest@gmail.com](mailto:subbulakshmibest@gmail.com) |

### Release v2.0.0 Contributors

| Name | Affiliation | Contact |
| :--- | :--- | :--- |
| **Rahul S** | IIIrd year B.Tech CSE, VIT Chennai | [rahulsaravanan3052@gmail.com](mailto:rahulsaravanan3052@gmail.com) |
| **Muthu Venkatesh M** | IIIrd year B.Tech CSE, VIT Chennai | [muthuvenkat2426@gmail.com](mailto:muthuvenkat2426@gmail.com) |
| **Rahul R** | IIIrd year B.Tech CSE, VIT Chennai | [rahulsubha1983@gmail.com](mailto:rahulsubha1983@gmail.com) |

See the [License](license.md) page for the full license text.
