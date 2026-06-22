import Link from 'next/link';
import { Shield, Zap, FileText, CheckCircle, ArrowRight, Lock, Globe, Code } from 'lucide-react';

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-900 to-slate-800 text-white">
      {/* Nav */}
      <nav className="flex items-center justify-between px-8 py-5 max-w-7xl mx-auto">
        <div className="flex items-center gap-2">
          <Shield className="w-7 h-7 text-blue-400" />
          <span className="text-xl font-bold">SecAudit</span>
        </div>
        <div className="flex items-center gap-4">
          <Link href="/auth/login" className="text-slate-300 hover:text-white transition-colors text-sm">
            Sign in
          </Link>
          <Link
            href="/auth/register"
            className="bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors"
          >
            Get Started Free
          </Link>
        </div>
      </nav>

      {/* Hero */}
      <main className="max-w-7xl mx-auto px-8 pt-20 pb-16 text-center">
        <div className="inline-flex items-center gap-2 bg-blue-500/10 border border-blue-500/30 rounded-full px-4 py-1.5 text-sm text-blue-300 mb-8">
          <Zap className="w-3.5 h-3.5" />
          No AI APIs required — $0 per scan
        </div>

        <h1 className="text-5xl md:text-6xl font-black mb-6 leading-tight">
          Is Your Website Ready<br />
          <span className="bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent">
            for Production?
          </span>
        </h1>
        <p className="text-xl text-slate-300 max-w-2xl mx-auto mb-10 leading-relaxed">
          Comprehensive security auditing platform. Scan any website, identify vulnerabilities,
          and get actionable remediation guidance — all in one place.
        </p>

        <div className="flex items-center justify-center gap-4 flex-wrap">
          <Link
            href="/auth/register"
            className="inline-flex items-center gap-2 bg-blue-500 hover:bg-blue-600 text-white px-8 py-3.5 rounded-xl font-semibold transition-colors text-base"
          >
            Start Free Scan <ArrowRight className="w-4 h-4" />
          </Link>
          <Link
            href="#features"
            className="inline-flex items-center gap-2 border border-slate-600 hover:border-slate-400 text-slate-300 hover:text-white px-8 py-3.5 rounded-xl font-semibold transition-colors text-base"
          >
            See Features
          </Link>
        </div>

        {/* Verdict badges */}
        <div className="flex items-center justify-center gap-4 mt-12 flex-wrap">
          <div className="bg-green-500/20 border border-green-500/40 rounded-full px-5 py-2 text-green-300 font-bold text-sm">
            ✓ GO
          </div>
          <div className="bg-yellow-500/20 border border-yellow-500/40 rounded-full px-5 py-2 text-yellow-300 font-bold text-sm">
            ⚠ GO WITH CONDITIONS
          </div>
          <div className="bg-red-500/20 border border-red-500/40 rounded-full px-5 py-2 text-red-300 font-bold text-sm">
            ✗ NO-GO
          </div>
        </div>
      </main>

      {/* Features */}
      <section id="features" className="max-w-7xl mx-auto px-8 py-20">
        <h2 className="text-3xl font-bold text-center mb-3">Everything You Need</h2>
        <p className="text-slate-400 text-center mb-12">
          Production-grade security scanning without the enterprise price tag
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {FEATURES.map((f) => (
            <div
              key={f.title}
              className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 hover:border-slate-500 transition-colors"
            >
              <div className="w-10 h-10 bg-blue-500/20 rounded-lg flex items-center justify-center mb-4">
                <f.icon className="w-5 h-5 text-blue-400" />
              </div>
              <h3 className="font-semibold text-white mb-2">{f.title}</h3>
              <p className="text-slate-400 text-sm leading-relaxed">{f.description}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Audit categories */}
      <section className="max-w-7xl mx-auto px-8 py-16 border-t border-slate-700">
        <h2 className="text-3xl font-bold text-center mb-10">What We Test</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {CATEGORIES.map((c) => (
            <div key={c} className="bg-slate-800/40 border border-slate-700 rounded-lg px-4 py-3 text-sm text-slate-300 flex items-center gap-2">
              <CheckCircle className="w-3.5 h-3.5 text-green-400 shrink-0" />
              {c}
            </div>
          ))}
        </div>
      </section>

      {/* CTA */}
      <section className="max-w-3xl mx-auto px-8 py-20 text-center">
        <h2 className="text-3xl font-bold mb-4">Start Your Security Audit Now</h2>
        <p className="text-slate-400 mb-8">
          No credit card required. Get your first scan result in minutes.
        </p>
        <Link
          href="/auth/register"
          className="inline-flex items-center gap-2 bg-blue-500 hover:bg-blue-600 text-white px-10 py-4 rounded-xl font-bold text-lg transition-colors"
        >
          Create Free Account <ArrowRight className="w-5 h-5" />
        </Link>
      </section>

      <footer className="border-t border-slate-700 py-8 text-center text-slate-500 text-sm">
        <p>© 2024 SecAudit Platform. Open-source security auditing.</p>
      </footer>
    </div>
  );
}

const FEATURES = [
  { title: 'TLS & HTTPS Analysis', description: 'Certificate validation, HSTS, cipher suites, protocol versions.', icon: Lock },
  { title: 'Vulnerability Scanning', description: 'Nuclei templates, SQLi, XSS, injection vulnerabilities.', icon: Shield },
  { title: 'Sensitive Data Exposure', description: 'Detect exposed .env files, .git, backups, and secrets.', icon: Globe },
  { title: 'Professional Reports', description: 'Downloadable PDF, JSON, and CSV reports with evidence.', icon: FileText },
  { title: 'CI/CD Integration', description: 'Gate deployments automatically via GitHub Actions.', icon: Code },
  { title: 'Deployment Verdict', description: 'Clear GO / GO WITH CONDITIONS / NO-GO decision.', icon: CheckCircle },
];

const CATEGORIES = [
  'TLS & HTTPS', 'Security Headers', 'SQL Injection', 'XSS', 'CSRF',
  'Clickjacking', 'Sensitive Exposure', 'Access Control', 'Server Hardening',
  'Directory Traversal', 'Cloud Security', 'Subdomain Takeover',
];
