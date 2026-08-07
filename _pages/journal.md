---
layout: page
title: journal
description: Solved challenges, quick findings, and things worth documenting
permalink: /journal
---

<ul class="blog-posts">
{% assign items = site.journal | sort: "date" | reverse %}
{% for entry in items %}
  <li>
    <span><i><time datetime="{{ entry.date | date_to_xmlschema }}">{{ entry.date | date: "%b %-d, %Y" }}</time></i></span>
    <a href="{{ entry.url | relative_url }}">{{ entry.title }}</a>
  </li>
{% endfor %}
{% if items.size == 0 %}
  <li><span></span><em>No entries yet.</em></li>
{% endif %}
</ul>
