export default function Home() {
  return (
    <main className="min-h-screen p-8">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-4xl font-bold mb-4">VardrMap</h1>
        <p className="text-lg mb-6">
          Attack surface mapping and threat-modeling workspace for bug bounty hunters.
        </p>

        <div className="border rounded-xl p-6">
          <h2 className="text-2xl font-semibold mb-2">MVP Direction</h2>
          <p>
            Organize targets, track testing hypotheses, manage findings, and integrate
            reconnaissance and enrichment APIs.
          </p>
        </div>
      </div>
    </main>
  );
}
