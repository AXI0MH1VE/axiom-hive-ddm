# Contributing to Axiom Hive DDM

Thank you for your interest in contributing to the DNS Defense Module! This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

We are committed to providing a welcoming and inclusive environment. All contributors are expected to:

- Be respectful and considerate
- Accept constructive criticism gracefully
- Focus on what is best for the community
- Show empathy towards other community members

## How to Contribute

### Reporting Bugs

If you find a bug, please create an issue with:

- **Clear title**: Summarize the issue in one line
- **Description**: Detailed explanation of the problem
- **Reproduction steps**: Step-by-step instructions to reproduce
- **Expected behavior**: What should happen
- **Actual behavior**: What actually happens
- **Environment**: OS, kernel version, eBPF/WFP version
- **Logs**: Relevant error messages or logs

### Suggesting Enhancements

We welcome feature requests and enhancement suggestions:

- **Use case**: Describe the problem you're trying to solve
- **Proposed solution**: Your idea for how to address it
- **Alternatives**: Other approaches you've considered
- **Impact**: Who would benefit from this enhancement

### Pull Requests

#### Before You Start

1. **Check existing issues**: Avoid duplicate work
2. **Discuss major changes**: Open an issue first for significant modifications
3. **Follow the roadmap**: Align with project goals and phases

#### Development Process

1. **Fork the repository**
   ```bash
   git clone https://github.com/axiom-hive/ddm.git
   cd ddm
   git remote add upstream https://github.com/axiom-hive/ddm.git
   ```

2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Write clean, readable code
   - Follow existing code style
   - Add comments for complex logic
   - Update documentation as needed

4. **Test your changes**
   ```bash
   # For eBPF changes
   cd examples/ebpf
   make clean && make
   sudo make test
   
   # For documentation changes
   # Verify Markdown rendering
   ```

5. **Commit your changes**
   ```bash
   git add .
   git commit -m "feat: add new entropy algorithm optimization"
   ```
   
   Use conventional commit messages:
   - `feat:` New feature
   - `fix:` Bug fix
   - `docs:` Documentation changes
   - `perf:` Performance improvements
   - `refactor:` Code refactoring
   - `test:` Test additions or modifications
   - `chore:` Maintenance tasks

6. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

7. **Create a Pull Request**
   - Provide a clear description
   - Reference related issues
   - Include test results
   - Add screenshots for UI changes

#### Code Review Process

- Maintainers will review your PR within 5 business days
- Address feedback promptly
- Keep discussions focused and professional
- Be patient—quality takes time

## Development Guidelines

### eBPF Code

- **Safety first**: Ensure verifier acceptance
- **Performance**: Minimize instruction count
- **Portability**: Test on multiple kernel versions
- **Documentation**: Comment non-obvious logic

```c
// Good: Clear, safe, documented
static __always_inline int parse_dns_query(
    struct __sk_buff *skb,
    struct dns_query *query
) {
    // Bounds check before every pointer access
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;  // Verifier-friendly error handling
    
    // ... rest of implementation
}
```

### Documentation

- **Clarity**: Write for diverse audiences (developers, operators, security teams)
- **Completeness**: Cover all important aspects
- **Examples**: Provide concrete, runnable examples
- **Diagrams**: Use Mermaid for architecture and flow diagrams

### Testing

- **Unit tests**: For individual functions
- **Integration tests**: For component interactions
- **Performance tests**: Measure overhead and throughput
- **Security tests**: Verify enforcement and evasion resistance

## Areas of Contribution

### High Priority

- **eBPF optimization**: Reduce instruction count, improve performance
- **Windows WFP driver**: Complete implementation and hardening
- **Merkle proof verification**: Optimize cryptographic operations
- **Hermetic resolver**: Full implementation with transparency logs
- **Wildcard matching**: Efficient algorithms for pattern matching

### Medium Priority

- **Documentation**: Expand guides, add tutorials
- **Testing**: Increase coverage, add benchmarks
- **Deployment automation**: Ansible, Terraform, Kubernetes operators
- **Monitoring integration**: Prometheus, Grafana dashboards
- **CLI tools**: User-friendly management interfaces

### Research and Exploration

- **Post-quantum cryptography**: Integrate PQ-safe algorithms
- **Hardware acceleration**: GPU/FPGA for entropy computation
- **Machine learning**: Automated manifold generation
- **Formal verification**: Prove security properties mathematically

## Communication

- **GitHub Issues**: Bug reports, feature requests
- **GitHub Discussions**: General questions, ideas, community support
- **Email**: security@axiom-hive.io for security vulnerabilities (see SECURITY.md)

## Recognition

Contributors will be recognized in:

- **CONTRIBUTORS.md**: List of all contributors
- **Release notes**: Acknowledgment of significant contributions
- **Documentation**: Author credits for major documentation work

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Questions?

If you have questions about contributing, feel free to:

- Open a GitHub Discussion
- Comment on relevant issues
- Reach out to maintainers

Thank you for helping make DDM better!
