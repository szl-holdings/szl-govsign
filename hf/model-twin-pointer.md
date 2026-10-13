---
license: apache-2.0
tags:
  - kernel
  - szl-holdings
---

<!-- Native artwork: szl-brand@4309f6fce89179331b0b3ed8c99494e76c5be256; Orbit v2 icon SHA-256 6e2b7d72a3af3d9602b79de41df0194ede6496a9661f057108ec224c0efc92e6. -->
<p><a href="https://github.com/szl-holdings"><img src="https://raw.githubusercontent.com/szl-holdings/szl-brand/4309f6fce89179331b0b3ed8c99494e76c5be256/kit/logos/orbit-v2/suite/szl-icon-32.svg" alt="SZL Holdings — Orbit v2" width="40" height="40" /></a></p>

<p><small>Orbit v2 artwork © SZL Holdings · <a href="https://github.com/szl-holdings/szl-brand/blob/4309f6fce89179331b0b3ed8c99494e76c5be256/kit/LICENSE">CC BY 4.0</a>. Page documentation remains Apache-2.0.</small></p>

# {{KERNEL_NAME}} has moved to the kernel repository

This model repository holds no loadable build. The `kernels` library (0.16 and later) loads
kernels only from the kernel repository:

**[{{KERNEL_URL}}]({{KERNEL_URL}})**

```python
# pip install "kernels>=0.17.2" torch cryptography
from kernels import get_kernel

kernel = get_kernel("{{REPO_ID}}", version={{KERNEL_VERSION}}, trust_remote_code=True)
```

The source of truth is [{{GITHUB_REPOSITORY}}](https://github.com/{{GITHUB_REPOSITORY}}).
Its `hf-kernel-publish` workflow builds the kernel, verifies it through `get_kernel`, and
then updates this pointer. Commits of this model repository are not kernel revisions.
