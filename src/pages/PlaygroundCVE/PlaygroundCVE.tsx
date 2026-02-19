
import { useState } from 'react';
import { motion } from 'framer-motion';
import {
    Bug, Search, Shield, Globe, Server, Code,
    Terminal, Lock, AlertTriangle, ArrowRight
} from 'lucide-react';
import Button from '@components/atoms/Button';

// Animation variants
const staggerContainer = {
    hidden: { opacity: 0 },
    visible: {
        opacity: 1,
        transition: {
            staggerChildren: 0.1
        }
    }
};

const staggerItem = {
    hidden: { opacity: 0, y: 20 },
    visible: {
        opacity: 1,
        y: 0,
        transition: { duration: 0.4 }
    }
};

interface CVE {
    id: string;
    cveId: string;
    title: string;
    severity: 'Critical' | 'High' | 'Medium' | 'Low';
    cvss: number;
    description: string;
    vector: string;
    year: number;
    category: string;
    icon: any;
    status: 'Available' | 'Coming Soon';
}

const CVES: CVE[] = [
    {
        id: 'log4shell',
        cveId: 'CVE-2021-44228',
        title: 'Log4Shell (Log4j RCE)',
        severity: 'Critical',
        cvss: 10.0,
        description: 'Remote Code Execution vulnerability in Apache Log4j 2. Attackers can execute arbitrary code by logging a malicious string containing a JNDI lookup.',
        vector: 'Network',
        year: 2021,
        category: 'Remote Code Execution',
        icon: Server,
        status: 'Available'
    },
    {
        id: 'spring4shell',
        cveId: 'CVE-2022-22965',
        title: 'Spring4Shell',
        severity: 'Critical',
        cvss: 9.8,
        description: 'Remote Code Execution in Spring Framework via Data Binding on JDK 9+. Allows attackers to load a malicious .jsp file.',
        vector: 'Network',
        year: 2022,
        category: 'Remote Code Execution',
        icon: Code,
        status: 'Available'
    },
    {
        id: 'heartbleed',
        cveId: 'CVE-2014-0160',
        title: 'Heartbleed',
        severity: 'High',
        cvss: 7.5,
        description: 'Information disclosure vulnerability in OpenSSL. Allows attackers to read memory of the server, potentially exposing keys and user data.',
        vector: 'Network',
        year: 2014,
        category: 'Information Disclosure',
        icon: Lock,
        status: 'Available'
    },
    {
        id: 'eternalblue',
        cveId: 'CVE-2017-0144',
        title: 'EternalBlue',
        severity: 'Critical',
        cvss: 9.3,
        description: 'Remote Code Execution vulnerability in Microsoft SMBv1 server. Used by WannaCry ransomware to spread across networks.',
        vector: 'Network',
        year: 2017,
        category: 'Remote Code Execution',
        icon: Terminal,
        status: 'Coming Soon'
    },
    {
        id: 'poodle',
        cveId: 'CVE-2014-3566',
        title: 'POODLE',
        severity: 'Medium',
        cvss: 4.3,
        description: 'Padding Oracle On Downgraded Legacy Encryption. Man-in-the-middle attack exploiting SSL 3.0 fallback.',
        vector: 'Network',
        year: 2014,
        category: 'Cryptographic Failure',
        icon: Shield,
        status: 'Coming Soon'
    }
];

export default function PlaygroundCVE() {
    const [searchTerm, setSearchTerm] = useState('');
    const [selectedSeverity, setSelectedSeverity] = useState('All');

    const filteredCVEs = CVES.filter(cve => {
        const matchesSearch = cve.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
            cve.cveId.toLowerCase().includes(searchTerm.toLowerCase()) ||
            cve.description.toLowerCase().includes(searchTerm.toLowerCase());
        const matchesSeverity = selectedSeverity === 'All' || cve.severity === selectedSeverity;

        return matchesSearch && matchesSeverity;
    });

    return (
        <div className="pt-32 pb-20">
            <div className="container-custom">
                {/* Hero Section */}
                <motion.div
                    className="text-center mb-20"
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.6 }}
                >
                    <div className="w-20 h-1 bg-gradient-to-r from-red-500 via-orange-500 to-yellow-500 mx-auto mb-8 rounded-full" />

                    <div className="inline-flex p-4 rounded-xl border border-red-500/20 bg-red-500/5 mb-6">
                        <Bug className="w-12 h-12 text-red-400" />
                    </div>

                    <h1 className="text-5xl lg:text-6xl font-bold mb-6">
                        <span className="text-white/90">CVE</span>{' '}
                        <span className="bg-gradient-to-r from-red-400 via-orange-400 to-yellow-400 bg-clip-text text-transparent">
                            Laboratory
                        </span>
                    </h1>

                    <p className="text-lg lg:text-xl text-gray-400 max-w-3xl mx-auto leading-relaxed mb-8">
                        Analyze, exploit, and patch famous Common Vulnerabilities and Exposures (CVEs)
                        in a safe, isolated sandboxed environment.
                    </p>

                    <div className="flex flex-wrap items-center justify-center gap-4 text-sm text-gray-500">
                        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-white/[0.03] border border-white/5">
                            <Shield className="w-4 h-4 text-emerald-400" />
                            <span>Safe Environment</span>
                        </div>
                        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-white/[0.03] border border-white/5">
                            <Globe className="w-4 h-4 text-blue-400" />
                            <span>Real-world Scenarios</span>
                        </div>
                        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-white/[0.03] border border-white/5">
                            <Terminal className="w-4 h-4 text-purple-400" />
                            <span>Hands-on Practice</span>
                        </div>
                    </div>
                </motion.div>

                {/* Filters */}
                <motion.div
                    className="flex flex-col md:flex-row gap-6 mb-12 items-center justify-between"
                    initial={{ opacity: 0, y: 10 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                >
                    <div className="relative w-full md:w-96">
                        <div className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400">
                            <Search className="w-5 h-5" />
                        </div>
                        <input
                            type="text"
                            placeholder="Search CVE ID, name, or description..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            className="w-full bg-white/[0.03] border border-white/10 rounded-xl pl-10 pr-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-red-500/50 focus:ring-1 focus:ring-red-500/30 transition-all"
                        />
                    </div>

                    <div className="flex items-center gap-2">
                        {['All', 'Critical', 'High', 'Medium', 'Low'].map((severity) => (
                            <button
                                key={severity}
                                onClick={() => setSelectedSeverity(severity)}
                                className={`px-4 py-2 rounded-lg text-sm font-semibold transition-all ${selectedSeverity === severity
                                    ? 'bg-red-500 text-white shadow-lg shadow-red-500/20'
                                    : 'bg-white/[0.05] text-gray-400 hover:text-white hover:bg-white/10'
                                    }`}
                            >
                                {severity}
                            </button>
                        ))}
                    </div>
                </motion.div>

                {/* CVE Grid */}
                <motion.div
                    className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"
                    variants={staggerContainer}
                    initial="hidden"
                    whileInView="visible"
                    viewport={{ once: true }}
                >
                    {filteredCVEs.map((cve) => {
                        const Icon = cve.icon;
                        return (
                            <motion.div
                                key={cve.id}
                                variants={staggerItem}
                                className="group relative rounded-xl border border-white/5 bg-white/[0.02] hover:bg-white/[0.05] hover:border-red-500/20 transition-all h-full flex flex-col overflow-hidden"
                            >
                                {/* Severity Stripe */}
                                <div className={`absolute top-0 left-0 w-1 h-full ${cve.severity === 'Critical' ? 'bg-red-600' :
                                    cve.severity === 'High' ? 'bg-orange-500' :
                                        cve.severity === 'Medium' ? 'bg-yellow-500' :
                                            'bg-blue-500'
                                    }`} />

                                <div className="p-6 flex-1 flex flex-col">
                                    {/* Header */}
                                    <div className="flex items-start justify-between mb-4">
                                        <div className="flex items-center gap-3">
                                            <div className="p-2.5 rounded-lg bg-white/[0.05] border border-white/10 text-gray-400 group-hover:text-white transition-colors">
                                                <Icon className="w-5 h-5" />
                                            </div>
                                            <div>
                                                <span className="block text-xs font-mono text-red-400 mb-0.5">{cve.cveId}</span>
                                                <span className="text-xs text-gray-500">{cve.year} • {cve.category}</span>
                                            </div>
                                        </div>

                                        <div className={`px-2.5 py-1 rounded-full text-xs font-bold border ${ // Fixed: wrapped expression in curly braces and $
                                            cve.severity === 'Critical' ? 'bg-red-500/10 text-red-400 border-red-500/20' :
                                                cve.severity === 'High' ? 'bg-orange-500/10 text-orange-400 border-orange-500/20' :
                                                    cve.severity === 'Medium' ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20' :
                                                        'bg-blue-500/10 text-blue-400 border-blue-500/20'
                                            }`}>
                                            CVSS {cve.cvss}
                                        </div>
                                    </div>

                                    <h3 className="text-xl font-bold text-white mb-3 group-hover:text-red-400 transition-colors">
                                        {cve.title}
                                    </h3>

                                    <p className="text-gray-400 text-sm leading-relaxed mb-6 flex-1">
                                        {cve.description}
                                    </p>

                                    <div className="mt-auto pt-4 border-t border-white/5 flex items-center justify-between">
                                        <div className="flex items-center gap-1.5 text-xs text-gray-500">
                                            <AlertTriangle className="w-3.5 h-3.5" />
                                            <span>{cve.vector} Vector</span>
                                        </div>

                                        {cve.status === 'Available' ? (
                                            <Button
                                                variant="outline"
                                                size="sm"
                                                className="border-red-500/20 text-red-400 hover:bg-red-500/10 hover:border-red-500/40"
                                                rightIcon={<ArrowRight className="w-4 h-4" />}
                                            >
                                                Start Lab
                                            </Button>
                                        ) : (
                                            <span className="text-xs font-semibold text-gray-600 px-3 py-1.5 rounded-lg bg-white/[0.02] border border-white/5 cursor-not-allowed">
                                                Coming Soon
                                            </span>
                                        )}
                                    </div>
                                </div>
                            </motion.div>
                        );
                    })}
                </motion.div>

                {/* Empty State */}
                {filteredCVEs.length === 0 && (
                    <div className="text-center py-20">
                        <div className="inline-flex p-4 rounded-full bg-white/[0.02] border border-white/5 mb-4">
                            <Search className="w-8 h-8 text-gray-600" />
                        </div>
                        <h3 className="text-xl font-bold text-white mb-2">No CVEs Found</h3>
                        <p className="text-gray-500">Try adjusting your search or filters.</p>
                    </div>
                )}
            </div>
        </div>
    );
}
