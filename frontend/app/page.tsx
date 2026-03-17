"use client";

import { useEffect, useState } from "react";

export default function Home() {
  const [targets, setTargets] = useState<any[]>([]);
  const [name, setName] = useState("");

  const API_URL = "https://vardrmap-production.up.railway.app";

  useEffect(() => {
    fetch(`${API_URL}/targets`)
      .then((res) => res.json())
      .then((data) => setTargets(data.targets))
      .catch(() => console.log("failed to fetch targets"));
  }, []);

  const addTarget = async () => {
    if (!name) return;

    await fetch(`${API_URL}/targets`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ name }),
    });

    setName("");

    const res = await fetch(`${API_URL}/targets`);
    const data = await res.json();
    setTargets(data.targets);
  };

  return (
    <main className="min-h-screen p-8">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-4xl font-bold mb-4">VardrMap</h1>

        <div className="mb-6">
          <input
            className="border p-2 mr-2"
            placeholder="Enter target name"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <button className="bg-black text-white px-4 py-2" onClick={addTarget}>
            Add Target
          </button>
        </div>

        <div className="border rounded-xl p-6">
          <h2 className="text-xl font-semibold mb-2">Targets</h2>
          <ul>
            {targets.map((t, i) => (
              <li key={i}>{t.name}</li>
            ))}
          </ul>
        </div>
      </div>
    </main>
  );
}