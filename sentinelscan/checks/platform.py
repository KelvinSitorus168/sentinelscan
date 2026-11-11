"""Guess hosting platform / stack from response headers so fixes can be tailored."""

from __future__ import annotations

from ..models import HttpResponse


def detect(responses: list[HttpResponse]) -> list[str]:
    found: list[str] = []

    def add(name: str) -> None:
        if name not in found:
            found.append(name)

    for r in responses:
        server = (r.get("server") or "").lower()
        powered = (r.get("x-powered-by") or "").lower()
        if r.get("x-vercel-id") or "vercel" in server:
            add("vercel")
        if r.get("x-nf-request-id") or "netlify" in server:
            add("netlify")
        if r.get("cf-ray") or "cloudflare" in server:
            add("cloudflare")
        if r.get("x-github-request-id") or "github.com" in server:
            add("github")
        if r.get("x-amz-cf-id"):
            add("cloudfront")
        if "nginx" in server:
            add("nginx")
        if "apache" in server:
            add("apache")
        if "litespeed" in server:
            add("litespeed")
        if "next.js" in powered or r.get("x-nextjs-cache") or r.get("x-nextjs-prerender"):
            add("nextjs")
        if "express" in powered:
            add("express")
        if "php" in powered:
            add("php")
    return found
