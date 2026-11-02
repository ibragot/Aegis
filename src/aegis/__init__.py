"""Aegis - AI-powered cloud security detection and investigation platform.

Data flows through the package like this:

    simulator  ->  collectors  ->  bus (Kafka)  ->  rules + ml  ->  detection (correlator)
               ->  graph  ->  investigator (RAG + LLM)  ->  api / dashboard

Every stage is a plain Python class so it can run either inside one process
(`aegis demo`, the tests) or as its own Kafka consumer service (`aegis run ...`).
"""

__version__ = "0.1.0"
