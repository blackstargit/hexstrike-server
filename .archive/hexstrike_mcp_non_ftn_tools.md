    @mcp.tool()
    def cloudmapper_analysis(action: str = "collect", account: str = "",
                            config: str = "config.json", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute CloudMapper for AWS network visualization and security analysis.

        Args:
            action: Action to perform (collect, prepare, webserver, find_admins, etc.)
            account: AWS account to analyze
            config: Configuration file path
            additional_args: Additional CloudMapper arguments

        Returns:
            AWS network visualization and security analysis results
        """
        data = {
            "action": action,
            "account": account,
            "config": config,
            "additional_args": additional_args
        }
        logger.info(f"☁️  Starting CloudMapper {action}")
        result = hexstrike_client.safe_post("api/tools/cloudmapper", data)
        if result.get("success"):
            logger.info(f"✅ CloudMapper {action} completed")
        else:
            logger.error(f"❌ CloudMapper {action} failed")
        return result

    @mcp.tool()
    def pacu_exploitation(session_name: str = "hexstrike_session", modules: str = "",
                         data_services: str = "", regions: str = "",
                         additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Pacu for AWS exploitation framework.

        Args:
            session_name: Pacu session name
            modules: Comma-separated list of modules to run
            data_services: Data services to enumerate
            regions: AWS regions to target
            additional_args: Additional Pacu arguments

        Returns:
            AWS exploitation framework results
        """
        data = {
            "session_name": session_name,
            "modules": modules,
            "data_services": data_services,
            "regions": regions,
            "additional_args": additional_args
        }
        logger.info(f"☁️  Starting Pacu AWS exploitation")
        result = hexstrike_client.safe_post("api/tools/pacu", data)
        if result.get("success"):
            logger.info(f"✅ Pacu exploitation completed")
        else:
            logger.error(f"❌ Pacu exploitation failed")
        return result

    @mcp.tool()
    def kube_hunter_scan(target: str = "", remote: str = "", cidr: str = "",
                        interface: str = "", active: bool = False, report: str = "json",
                        additional_args: str = "") -> Dict[str, Any]:
        """
        Execute kube-hunter for Kubernetes penetration testing.

        Args:
            target: Specific target to scan
            remote: Remote target to scan
            cidr: CIDR range to scan
            interface: Network interface to scan
            active: Enable active hunting (potentially harmful)
            report: Report format (json, yaml)
            additional_args: Additional kube-hunter arguments

        Returns:
            Kubernetes penetration testing results
        """
        data = {
            "target": target,
            "remote": remote,
            "cidr": cidr,
            "interface": interface,
            "active": active,
            "report": report,
            "additional_args": additional_args
        }
        logger.info(f"☁️  Starting kube-hunter Kubernetes scan")
        result = hexstrike_client.safe_post("api/tools/kube-hunter", data)
        if result.get("success"):
            logger.info(f"✅ kube-hunter scan completed")
        else:
            logger.error(f"❌ kube-hunter scan failed")
        return result

    @mcp.tool()
    def kube_bench_cis(targets: str = "", version: str = "", config_dir: str = "",
                      output_format: str = "json", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute kube-bench for CIS Kubernetes benchmark checks.

        Args:
            targets: Targets to check (master, node, etcd, policies)
            version: Kubernetes version
            config_dir: Configuration directory
            output_format: Output format (json, yaml)
            additional_args: Additional kube-bench arguments

        Returns:
            CIS Kubernetes benchmark results
        """
        data = {
            "targets": targets,
            "version": version,
            "config_dir": config_dir,
            "output_format": output_format,
            "additional_args": additional_args
        }
        logger.info(f"☁️  Starting kube-bench CIS benchmark")
        result = hexstrike_client.safe_post("api/tools/kube-bench", data)
        if result.get("success"):
            logger.info(f"✅ kube-bench benchmark completed")
        else:
            logger.error(f"❌ kube-bench benchmark failed")
        return result

    @mcp.tool()
    def docker_bench_security_scan(checks: str = "", exclude: str = "",
                                  output_file: str = "/tmp/docker-bench-results.json",
                                  additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Docker Bench for Security for Docker security assessment.

        Args:
            checks: Specific checks to run
            exclude: Checks to exclude
            output_file: Output file path
            additional_args: Additional Docker Bench arguments

        Returns:
            Docker security assessment results
        """
        data = {
            "checks": checks,
            "exclude": exclude,
            "output_file": output_file,
            "additional_args": additional_args
        }
        logger.info(f"🐳 Starting Docker Bench Security assessment")
        result = hexstrike_client.safe_post("api/tools/docker-bench-security", data)
        if result.get("success"):
            logger.info(f"✅ Docker Bench Security completed")
        else:
            logger.error(f"❌ Docker Bench Security failed")
        return result

    @mcp.tool()
    def clair_vulnerability_scan(image: str, config: str = "/etc/clair/config.yaml",
                                output_format: str = "json", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Clair for container vulnerability analysis.

        Args:
            image: Container image to scan
            config: Clair configuration file
            output_format: Output format (json, yaml)
            additional_args: Additional Clair arguments

        Returns:
            Container vulnerability analysis results
        """
        data = {
            "image": image,
            "config": config,
            "output_format": output_format,
            "additional_args": additional_args
        }
        logger.info(f"🐳 Starting Clair vulnerability scan: {image}")
        result = hexstrike_client.safe_post("api/tools/clair", data)
        if result.get("success"):
            logger.info(f"✅ Clair scan completed for {image}")
        else:
            logger.error(f"❌ Clair scan failed for {image}")
        return result

    @mcp.tool()
    def falco_runtime_monitoring(config_file: str = "/etc/falco/falco.yaml",
                                rules_file: str = "", output_format: str = "json",
                                duration: int = 60, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Falco for runtime security monitoring.

        Args:
            config_file: Falco configuration file
            rules_file: Custom rules file
            output_format: Output format (json, text)
            duration: Monitoring duration in seconds
            additional_args: Additional Falco arguments

        Returns:
            Runtime security monitoring results
        """
        data = {
            "config_file": config_file,
            "rules_file": rules_file,
            "output_format": output_format,
            "duration": duration,
            "additional_args": additional_args
        }
        logger.info(f"🛡️  Starting Falco runtime monitoring for {duration}s")
        result = hexstrike_client.safe_post("api/tools/falco", data)
        if result.get("success"):
            logger.info(f"✅ Falco monitoring completed")
        else:
            logger.error(f"❌ Falco monitoring failed")
        return result

    @mcp.tool()
    def checkov_iac_scan(directory: str = ".", framework: str = "", check: str = "",
                        skip_check: str = "", output_format: str = "json",
                        additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Checkov for infrastructure as code security scanning.

        Args:
            directory: Directory to scan
            framework: Framework to scan (terraform, cloudformation, kubernetes, etc.)
            check: Specific check to run
            skip_check: Check to skip
            output_format: Output format (json, yaml, cli)
            additional_args: Additional Checkov arguments

        Returns:
            Infrastructure as code security scanning results
        """
        data = {
            "directory": directory,
            "framework": framework,
            "check": check,
            "skip_check": skip_check,
            "output_format": output_format,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting Checkov IaC scan: {directory}")
        result = hexstrike_client.safe_post("api/tools/checkov", data)
        if result.get("success"):
            logger.info(f"✅ Checkov scan completed")
        else:
            logger.error(f"❌ Checkov scan failed")
        return result

    @mcp.tool()
    def terrascan_iac_scan(scan_type: str = "all", iac_dir: str = ".",
                          policy_type: str = "", output_format: str = "json",
                          severity: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Terrascan for infrastructure as code security scanning.

        Args:
            scan_type: Type of scan (all, terraform, k8s, etc.)
            iac_dir: Infrastructure as code directory
            policy_type: Policy type to use
            output_format: Output format (json, yaml, xml)
            severity: Severity filter (high, medium, low)
            additional_args: Additional Terrascan arguments

        Returns:
            Infrastructure as code security scanning results
        """
        data = {
            "scan_type": scan_type,
            "iac_dir": iac_dir,
            "policy_type": policy_type,
            "output_format": output_format,
            "severity": severity,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting Terrascan IaC scan: {iac_dir}")
        result = hexstrike_client.safe_post("api/tools/terrascan", data)
        if result.get("success"):
            logger.info(f"✅ Terrascan scan completed")
        else:
            logger.error(f"❌ Terrascan scan failed")
        return result

    @mcp.tool()
    def arp_scan_discovery(target: str = "", interface: str = "", local_network: bool = False,
                          timeout: int = 500, retry: int = 3, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute arp-scan for network discovery with enhanced logging.

        Args:
            target: The target IP range (if not using local_network)
            interface: Network interface to use
            local_network: Scan local network
            timeout: Timeout in milliseconds
            retry: Number of retries
            additional_args: Additional arp-scan arguments

        Returns:
            Network discovery results via ARP scanning
        """
        data = {
            "target": target,
            "interface": interface,
            "local_network": local_network,
            "timeout": timeout,
            "retry": retry,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting arp-scan: {target if target else 'local network'}")
        result = hexstrike_client.safe_post("api/tools/arp-scan", data)
        if result.get("success"):
            logger.info(f"✅ arp-scan completed")
        else:
            logger.error(f"❌ arp-scan failed")
        return result

    @mcp.tool()
    def volatility_analyze(memory_file: str, plugin: str, profile: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Volatility for memory forensics analysis with enhanced logging.

        Args:
            memory_file: Path to memory dump file
            plugin: Volatility plugin to use
            profile: Memory profile to use
            additional_args: Additional Volatility arguments

        Returns:
            Memory forensics analysis results
        """
        data = {
            "memory_file": memory_file,
            "plugin": plugin,
            "profile": profile,
            "additional_args": additional_args
        }
        logger.info(f"🧠 Starting Volatility analysis: {plugin}")
        result = hexstrike_client.safe_post("api/tools/volatility", data)
        if result.get("success"):
            logger.info(f"✅ Volatility analysis completed")
        else:
            logger.error(f"❌ Volatility analysis failed")
        return result

    @mcp.tool()
    def volatility3_analyze(memory_file: str, plugin: str, output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Volatility3 for advanced memory forensics with enhanced logging.

        Args:
            memory_file: Path to memory dump file
            plugin: Volatility3 plugin to execute
            output_file: Output file path
            additional_args: Additional Volatility3 arguments

        Returns:
            Advanced memory forensics results
        """
        data = {
            "memory_file": memory_file,
            "plugin": plugin,
            "output_file": output_file,
            "additional_args": additional_args
        }
        logger.info(f"🧠 Starting Volatility3 analysis: {plugin}")
        result = hexstrike_client.safe_post("api/tools/volatility3", data)
        if result.get("success"):
            logger.info(f"✅ Volatility3 analysis completed")
        else:
            logger.error(f"❌ Volatility3 analysis failed")
        return result

    @mcp.tool()
    def radare2_analyze(binary: str, commands: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Radare2 for binary analysis and reverse engineering with enhanced logging.

        Args:
            binary: Path to the binary file
            commands: Radare2 commands to execute
            additional_args: Additional Radare2 arguments

        Returns:
            Binary analysis results
        """
        data = {
            "binary": binary,
            "commands": commands,
            "additional_args": additional_args
        }
        logger.info(f"🔧 Starting Radare2 analysis: {binary}")
        result = hexstrike_client.safe_post("api/tools/radare2", data)
        if result.get("success"):
            logger.info(f"✅ Radare2 analysis completed for {binary}")
        else:
            logger.error(f"❌ Radare2 analysis failed for {binary}")
        return result

    @mcp.tool()
    def binwalk_analyze(file_path: str, extract: bool = False, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Binwalk for firmware and file analysis with enhanced logging.

        Args:
            file_path: Path to the file to analyze
            extract: Whether to extract discovered files
            additional_args: Additional Binwalk arguments

        Returns:
            Firmware analysis results
        """
        data = {
            "file_path": file_path,
            "extract": extract,
            "additional_args": additional_args
        }
        logger.info(f"🔧 Starting Binwalk analysis: {file_path}")
        result = hexstrike_client.safe_post("api/tools/binwalk", data)
        if result.get("success"):
            logger.info(f"✅ Binwalk analysis completed for {file_path}")
        else:
            logger.error(f"❌ Binwalk analysis failed for {file_path}")
        return result

    @mcp.tool()
    def xxd_hexdump(file_path: str, offset: str = "0", length: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Create a hex dump of a file using xxd with enhanced logging.

        Args:
            file_path: Path to the file
            offset: Offset to start reading from
            length: Number of bytes to read
            additional_args: Additional xxd arguments

        Returns:
            Hex dump results
        """
        data = {
            "file_path": file_path,
            "offset": offset,
            "length": length,
            "additional_args": additional_args
        }
        logger.info(f"🔧 Starting XXD hex dump: {file_path}")
        result = hexstrike_client.safe_post("api/tools/xxd", data)
        if result.get("success"):
            logger.info(f"✅ XXD hex dump completed for {file_path}")
        else:
            logger.error(f"❌ XXD hex dump failed for {file_path}")
        return result

    @mcp.tool()
    def one_gadget_search(libc_path: str, level: int = 1, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute one_gadget to find one-shot RCE gadgets in libc.

        Args:
            libc_path: Path to libc binary
            level: Constraint level (0, 1, 2)
            additional_args: Additional one_gadget arguments

        Returns:
            One-shot RCE gadget search results
        """
        data = {
            "libc_path": libc_path,
            "level": level,
            "additional_args": additional_args
        }
        logger.info(f"🔧 Starting one_gadget analysis: {libc_path}")
        result = hexstrike_client.safe_post("api/tools/one-gadget", data)
        if result.get("success"):
            logger.info(f"✅ one_gadget analysis completed")
        else:
            logger.error(f"❌ one_gadget analysis failed")
        return result

    @mcp.tool()
    def ropper_gadget_search(binary: str, gadget_type: str = "rop", quality: int = 1,
                            arch: str = "", search_string: str = "",
                            additional_args: str = "") -> Dict[str, Any]:
        """
        Execute ropper for advanced ROP/JOP gadget searching.

        Args:
            binary: Binary to search for gadgets
            gadget_type: Type of gadgets (rop, jop, sys, all)
            quality: Gadget quality level (1-5)
            arch: Target architecture (x86, x86_64, arm, etc.)
            search_string: Specific gadget pattern to search for
            additional_args: Additional ropper arguments

        Returns:
            Advanced ROP/JOP gadget search results
        """
        data = {
            "binary": binary,
            "gadget_type": gadget_type,
            "quality": quality,
            "arch": arch,
            "search_string": search_string,
            "additional_args": additional_args
        }
        logger.info(f"🔧 Starting ropper analysis: {binary}")
        result = hexstrike_client.safe_post("api/tools/ropper", data)
        if result.get("success"):
            logger.info(f"✅ ropper analysis completed")
        else:
            logger.error(f"❌ ropper analysis failed")
        return result

    @mcp.tool()
    def pwninit_setup(binary: str, libc: str = "", ld: str = "",
                     template_type: str = "python", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute pwninit for CTF binary exploitation setup.

        Args:
            binary: Binary file to set up
            libc: Libc file to use
            ld: Loader file to use
            template_type: Template type (python, c)
            additional_args: Additional pwninit arguments

        Returns:
            CTF binary exploitation setup results
        """
        data = {
            "binary": binary,
            "libc": libc,
            "ld": ld,
            "template_type": template_type,
            "additional_args": additional_args
        }
        logger.info(f"🔧 Starting pwninit setup: {binary}")
        result = hexstrike_client.safe_post("api/tools/pwninit", data)
        if result.get("success"):
            logger.info(f"✅ pwninit setup completed")
        else:
            logger.error(f"❌ pwninit setup failed")
        return result

    @mcp.tool()
    def dotdotpwn_scan(target: str, module: str = "http", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute DotDotPwn for directory traversal testing with enhanced logging.

        Args:
            target: The target hostname or IP
            module: Module to use (http, ftp, tftp, etc.)
            additional_args: Additional DotDotPwn arguments

        Returns:
            Directory traversal test results
        """
        data = {
            "target": target,
            "module": module,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting DotDotPwn scan: {target}")
        result = hexstrike_client.safe_post("api/tools/dotdotpwn", data)
        if result.get("success"):
            logger.info(f"✅ DotDotPwn scan completed for {target}")
        else:
            logger.error(f"❌ DotDotPwn scan failed for {target}")
        return result

    @mcp.tool()
    def xsser_scan(url: str, params: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute XSSer for XSS vulnerability testing with enhanced logging.

        Args:
            url: The target URL
            params: Parameters to test
            additional_args: Additional XSSer arguments

        Returns:
            XSS vulnerability test results
        """
        data = {
            "url": url,
            "params": params,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting XSSer scan: {url}")
        result = hexstrike_client.safe_post("api/tools/xsser", data)
        if result.get("success"):
            logger.info(f"✅ XSSer scan completed for {url}")
        else:
            logger.error(f"❌ XSSer scan failed for {url}")
        return result

    @mcp.tool()
    def wfuzz_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Wfuzz for web application fuzzing with enhanced logging.

        Args:
            url: The target URL (use FUZZ where you want to inject payloads)
            wordlist: Wordlist file to use
            additional_args: Additional Wfuzz arguments

        Returns:
            Web application fuzzing results
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting Wfuzz scan: {url}")
        result = hexstrike_client.safe_post("api/tools/wfuzz", data)
        if result.get("success"):
            logger.info(f"✅ Wfuzz scan completed for {url}")
        else:
            logger.error(f"❌ Wfuzz scan failed for {url}")
        return result

    @mcp.tool()
    def gau_discovery(domain: str, providers: str = "wayback,commoncrawl,otx,urlscan",
                     include_subs: bool = True, blacklist: str = "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico",
                     additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Gau (Get All URLs) for URL discovery from multiple sources with enhanced logging.

        Args:
            domain: The target domain
            providers: Data providers to use
            include_subs: Include subdomains
            blacklist: File extensions to blacklist
            additional_args: Additional Gau arguments

        Returns:
            Comprehensive URL discovery results from multiple sources
        """
        data = {
            "domain": domain,
            "providers": providers,
            "include_subs": include_subs,
            "blacklist": blacklist,
            "additional_args": additional_args
        }
        logger.info(f"📡 Starting Gau URL discovery: {domain}")
        result = hexstrike_client.safe_post("api/tools/gau", data)
        if result.get("success"):
            logger.info(f"✅ Gau URL discovery completed for {domain}")
        else:
            logger.error(f"❌ Gau URL discovery failed for {domain}")
        return result

    @mcp.tool()
    def waybackurls_discovery(domain: str, get_versions: bool = False,
                             no_subs: bool = False, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Waybackurls for historical URL discovery with enhanced logging.

        Args:
            domain: The target domain
            get_versions: Get all versions of URLs
            no_subs: Don't include subdomains
            additional_args: Additional Waybackurls arguments

        Returns:
            Historical URL discovery results from Wayback Machine
        """
        data = {
            "domain": domain,
            "get_versions": get_versions,
            "no_subs": no_subs,
            "additional_args": additional_args
        }
        logger.info(f"🕰️  Starting Waybackurls discovery: {domain}")
        result = hexstrike_client.safe_post("api/tools/waybackurls", data)
        if result.get("success"):
            logger.info(f"✅ Waybackurls discovery completed for {domain}")
        else:
            logger.error(f"❌ Waybackurls discovery failed for {domain}")
        return result

    @mcp.tool()
    def x8_parameter_discovery(url: str, wordlist: str = "/usr/share/wordlists/x8/params.txt",
                              method: str = "GET", body: str = "", headers: str = "",
                              additional_args: str = "") -> Dict[str, Any]:
        """
        Execute x8 for hidden parameter discovery with enhanced logging.

        Args:
            url: The target URL
            wordlist: Parameter wordlist
            method: HTTP method
            body: Request body
            headers: Custom headers
            additional_args: Additional x8 arguments

        Returns:
            Hidden parameter discovery results
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "method": method,
            "body": body,
            "headers": headers,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting x8 parameter discovery: {url}")
        result = hexstrike_client.safe_post("api/tools/x8", data)
        if result.get("success"):
            logger.info(f"✅ x8 parameter discovery completed for {url}")
        else:
            logger.error(f"❌ x8 parameter discovery failed for {url}")
        return result

    @mcp.tool()
    def jaeles_vulnerability_scan(url: str, signatures: str = "", config: str = "",
                                 threads: int = 20, timeout: int = 20,
                                 additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Jaeles for advanced vulnerability scanning with custom signatures.

        Args:
            url: The target URL
            signatures: Custom signature path
            config: Configuration file
            threads: Number of threads
            timeout: Request timeout
            additional_args: Additional Jaeles arguments

        Returns:
            Advanced vulnerability scanning results with custom signatures
        """
        data = {
            "url": url,
            "signatures": signatures,
            "config": config,
            "threads": threads,
            "timeout": timeout,
            "additional_args": additional_args
        }
        logger.info(f"🔬 Starting Jaeles vulnerability scan: {url}")
        result = hexstrike_client.safe_post("api/tools/jaeles", data)
        if result.get("success"):
            logger.info(f"✅ Jaeles vulnerability scan completed for {url}")
        else:
            logger.error(f"❌ Jaeles vulnerability scan failed for {url}")
        return result

    @mcp.tool()
    def anew_data_processing(input_data: str, output_file: str = "",
                            additional_args: str = "") -> Dict[str, Any]:
        """
        Execute anew for appending new lines to files (useful for data processing).

        Args:
            input_data: Input data to process
            output_file: Output file path
            additional_args: Additional anew arguments

        Returns:
            Data processing results with unique line filtering
        """
        data = {
            "input_data": input_data,
            "output_file": output_file,
            "additional_args": additional_args
        }
        logger.info("📝 Starting anew data processing")
        result = hexstrike_client.safe_post("api/tools/anew", data)
        if result.get("success"):
            logger.info("✅ anew data processing completed")
        else:
            logger.error("❌ anew data processing failed")
        return result

    @mcp.tool()
    def qsreplace_parameter_replacement(urls: str, replacement: str = "FUZZ",
                                       additional_args: str = "") -> Dict[str, Any]:
        """
        Execute qsreplace for query string parameter replacement.

        Args:
            urls: URLs to process
            replacement: Replacement string for parameters
            additional_args: Additional qsreplace arguments

        Returns:
            Parameter replacement results for fuzzing
        """
        data = {
            "urls": urls,
            "replacement": replacement,
            "additional_args": additional_args
        }
        logger.info("🔄 Starting qsreplace parameter replacement")
        result = hexstrike_client.safe_post("api/tools/qsreplace", data)
        if result.get("success"):
            logger.info("✅ qsreplace parameter replacement completed")
        else:
            logger.error("❌ qsreplace parameter replacement failed")
        return result

    @mcp.tool()
    def uro_url_filtering(urls: str, whitelist: str = "", blacklist: str = "",
                         additional_args: str = "") -> Dict[str, Any]:
        """
        Execute uro for filtering out similar URLs.

        Args:
            urls: URLs to filter
            whitelist: Whitelist patterns
            blacklist: Blacklist patterns
            additional_args: Additional uro arguments

        Returns:
            Filtered URL results with duplicates removed
        """
        data = {
            "urls": urls,
            "whitelist": whitelist,
            "blacklist": blacklist,
            "additional_args": additional_args
        }
        logger.info("🔍 Starting uro URL filtering")
        result = hexstrike_client.safe_post("api/tools/uro", data)
        if result.get("success"):
            logger.info("✅ uro URL filtering completed")
        else:
            logger.error("❌ uro URL filtering failed")
        return result

    @mcp.tool()
    def hakrawler_crawl(url: str, depth: int = 2, forms: bool = True, robots: bool = True, sitemap: bool = True, wayback: bool = False, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Hakrawler for web endpoint discovery with enhanced logging.

        Note: Uses standard Kali Linux hakrawler (hakluke/hakrawler) with parameter mapping:
        - url: Piped via echo to stdin (not -url flag)
        - depth: Mapped to -d flag (not -depth)
        - forms: Mapped to -s flag for showing sources
        - robots/sitemap/wayback: Mapped to -subs for subdomain inclusion
        - Always includes -u for unique URLs

        Args:
            url: Target URL to crawl
            depth: Crawling depth (mapped to -d)
            forms: Include forms in crawling (mapped to -s)
            robots: Check robots.txt (mapped to -subs)
            sitemap: Check sitemap.xml (mapped to -subs)
            wayback: Use Wayback Machine (mapped to -subs)
            additional_args: Additional Hakrawler arguments

        Returns:
            Web endpoint discovery results
        """
        data = {
            "url": url,
            "depth": depth,
            "forms": forms,
            "robots": robots,
            "sitemap": sitemap,
            "wayback": wayback,
            "additional_args": additional_args
        }
        logger.info(f"🕷️ Starting Hakrawler crawling: {url}")
        result = hexstrike_client.safe_post("api/tools/hakrawler", data)
        if result.get("success"):
            logger.info(f"✅ Hakrawler crawling completed")
        else:
            logger.error(f"❌ Hakrawler crawling failed")
        return result

    @mcp.tool()
    def hashpump_attack(signature: str, data: str, key_length: str, append_data: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute HashPump for hash length extension attacks with enhanced logging.

        Args:
            signature: Original hash signature
            data: Original data
            key_length: Length of secret key
            append_data: Data to append
            additional_args: Additional HashPump arguments

        Returns:
            Hash length extension attack results
        """
        data = {
            "signature": signature,
            "data": data,
            "key_length": key_length,
            "append_data": append_data,
            "additional_args": additional_args
        }
        logger.info(f"🔐 Starting HashPump attack")
        result = hexstrike_client.safe_post("api/tools/hashpump", data)
        if result.get("success"):
            logger.info(f"✅ HashPump attack completed")
        else:
            logger.error(f"❌ HashPump attack failed")
        return result

    @mcp.tool()
    def exiftool_extract(file_path: str, output_format: str = "", tags: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute ExifTool for metadata extraction with enhanced logging.

        Args:
            file_path: Path to file for metadata extraction
            output_format: Output format (json, xml, csv)
            tags: Specific tags to extract
            additional_args: Additional ExifTool arguments

        Returns:
            Metadata extraction results
        """
        data = {
            "file_path": file_path,
            "output_format": output_format,
            "tags": tags,
            "additional_args": additional_args
        }
        logger.info(f"📷 Starting ExifTool analysis: {file_path}")
        result = hexstrike_client.safe_post("api/tools/exiftool", data)
        if result.get("success"):
            logger.info(f"✅ ExifTool analysis completed")
        else:
            logger.error(f"❌ ExifTool analysis failed")
        return result

    @mcp.tool()
    def zap_scan(target: str = "", scan_type: str = "baseline", api_key: str = "", daemon: bool = False, port: str = "8090", host: str = "0.0.0.0", format_type: str = "xml", output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute OWASP ZAP with enhanced logging.

        Args:
            target: Target URL
            scan_type: Type of scan (baseline, full, api)
            api_key: ZAP API key
            daemon: Run in daemon mode
            port: Port for ZAP daemon
            host: Host for ZAP daemon
            format_type: Output format (xml, json, html)
            output_file: Output file path
            additional_args: Additional ZAP arguments

        Returns:
            ZAP scan results
        """
        data = {
            "target": target,
            "scan_type": scan_type,
            "api_key": api_key,
            "daemon": daemon,
            "port": port,
            "host": host,
            "format": format_type,
            "output_file": output_file,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting ZAP scan: {target}")
        result = hexstrike_client.safe_post("api/tools/zap", data)
        if result.get("success"):
            logger.info(f"✅ ZAP scan completed for {target}")
        else:
            logger.error(f"❌ ZAP scan failed for {target}")
        return result

    @mcp.tool()
    def prowler_scan(provider: str = "aws", profile: str = "default", region: str = "", checks: str = "", output_dir: str = "/tmp/prowler_output", output_format: str = "json", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Prowler for comprehensive cloud security assessment.

        Args:
            provider: Cloud provider (aws, azure, gcp)
            profile: AWS profile to use
            region: Specific region to scan
            checks: Specific checks to run
            output_dir: Directory to save results
            output_format: Output format (json, csv, html)
            additional_args: Additional Prowler arguments

        Returns:
            Cloud security assessment results
        """
        data = {
            "provider": provider,
            "profile": profile,
            "region": region,
            "checks": checks,
            "output_dir": output_dir,
            "output_format": output_format,
            "additional_args": additional_args
        }
        logger.info(f"☁️  Starting Prowler {provider} security assessment")
        result = hexstrike_client.safe_post("api/tools/prowler", data)
        if result.get("success"):
            logger.info(f"✅ Prowler assessment completed")
        else:
            logger.error(f"❌ Prowler assessment failed")
        return result

    @mcp.tool()
    def scout_suite_assessment(provider: str = "aws", profile: str = "default",
                              report_dir: str = "/tmp/scout-suite", services: str = "",
                              exceptions: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Scout Suite for multi-cloud security assessment.

        Args:
            provider: Cloud provider (aws, azure, gcp, aliyun, oci)
            profile: AWS profile to use
            report_dir: Directory to save reports
            services: Specific services to assess
            exceptions: Exceptions file path
            additional_args: Additional Scout Suite arguments

        Returns:
            Multi-cloud security assessment results
        """
        data = {
            "provider": provider,
            "profile": profile,
            "report_dir": report_dir,
            "services": services,
            "exceptions": exceptions,
            "additional_args": additional_args
        }
        logger.info(f"☁️  Starting Scout Suite {provider} assessment")
        result = hexstrike_client.safe_post("api/tools/scout-suite", data)
        if result.get("success"):
            logger.info(f"✅ Scout Suite assessment completed")
        else:
            logger.error(f"❌ Scout Suite assessment failed")
        return result

    @mcp.tool()
    def paramspider_mining(domain: str, level: int = 2,
                          exclude: str = "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico",
                          output: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute ParamSpider for parameter mining from web archives with enhanced logging.

        Args:
            domain: The target domain
            level: Mining level depth
            exclude: File extensions to exclude
            output: Output file path
            additional_args: Additional ParamSpider arguments

        Returns:
            Parameter mining results from web archives
        """
        data = {
            "domain": domain,
            "level": level,
            "exclude": exclude,
            "output": output,
            "additional_args": additional_args
        }
        logger.info(f"🕷️  Starting ParamSpider mining: {domain}")
        result = hexstrike_client.safe_post("api/tools/paramspider", data)
        if result.get("success"):
            logger.info(f"✅ ParamSpider mining completed for {domain}")
        else:
            logger.error(f"❌ ParamSpider mining failed for {domain}")
        return result

    @mcp.tool()
    def paramspider_discovery(domain: str, exclude: str = "", output_file: str = "", level: int = 2, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute ParamSpider for parameter discovery with enhanced logging.

        Args:
            domain: Target domain
            exclude: Extensions to exclude
            output_file: Output file path
            level: Crawling level
            additional_args: Additional ParamSpider arguments

        Returns:
            Parameter discovery results
        """
        data = {
            "domain": domain,
            "exclude": exclude,
            "output_file": output_file,
            "level": level,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting ParamSpider discovery: {domain}")
        result = hexstrike_client.safe_post("api/tools/paramspider", data)
        if result.get("success"):
            logger.info(f"✅ ParamSpider discovery completed")
        else:
            logger.error(f"❌ ParamSpider discovery failed")
        return result

    @mcp.tool()
    def burpsuite_scan(project_file: str = "", config_file: str = "", target: str = "", headless: bool = False, scan_type: str = "", scan_config: str = "", output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Burp Suite with enhanced logging.

        Args:
            project_file: Burp project file path
            config_file: Burp configuration file path
            target: Target URL
            headless: Run in headless mode
            scan_type: Type of scan to perform
            scan_config: Scan configuration
            output_file: Output file path
            additional_args: Additional Burp Suite arguments

        Returns:
            Burp Suite scan results
        """
        data = {
            "project_file": project_file,
            "config_file": config_file,
            "target": target,
            "headless": headless,
            "scan_type": scan_type,
            "scan_config": scan_config,
            "output_file": output_file,
            "additional_args": additional_args
        }
        logger.info(f"🔍 Starting Burp Suite scan")
        result = hexstrike_client.safe_post("api/tools/burpsuite", data)
        if result.get("success"):
            logger.info(f"✅ Burp Suite scan completed")
        else:
            logger.error(f"❌ Burp Suite scan failed")
        return result

# Duplicate httpx_probe:

    @mcp.tool()
    def httpx_probe(target: str, probe: bool = True, tech_detect: bool = False,
                   status_code: bool = False, content_length: bool = False,
                   title: bool = False, web_server: bool = False, threads: int = 50,
                   additional_args: str = "") -> Dict[str, Any]:
        """
        Execute httpx for fast HTTP probing and technology detection.

        Args:
            target: Target file or single URL
            probe: Enable probing
            tech_detect: Enable technology detection
            status_code: Show status codes
            content_length: Show content length
            title: Show page titles
            web_server: Show web server
            threads: Number of threads
            additional_args: Additional httpx arguments

        Returns:
            Fast HTTP probing results with technology detection
        """
        data = {
            "target": target,
            "probe": probe,
            "tech_detect": tech_detect,
            "status_code": status_code,
            "content_length": content_length,
            "title": title,
            "web_server": web_server,
            "threads": threads,
            "additional_args": additional_args
        }
        logger.info(f"🌍 Starting httpx probe: {target}")
        result = hexstrike_client.safe_post("api/tools/httpx", data)
        if result.get("success"):
            logger.info(f"✅ httpx probe completed for {target}")
        else:
            logger.error(f"❌ httpx probe failed for {target}")
        return result

