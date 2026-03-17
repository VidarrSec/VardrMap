"use client";

import { useEffect, useState } from "react";

export default function Home() {
  const [message, setMessage] = useState("Loading...");

  useEffect(() => {
    fetch("https://vardrmap-production.up.railway.app/")
      .then((res) => res.json())
      .then((data) => setMessage(data.message))
      .catch(() => setMessage("Failed to connect to API"));
  }, []);

  return (
    <main className="min-h-screen p-8">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-4xl font-bold mb-4">VardrMap</h1>

        <p className="text-lg mb-6">
          Backend response:
        </p>

        <div className="border rounded-xl p-6">
          {message}
        </div>
      </div>
    </main>
  );
}
