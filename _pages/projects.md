---
layout: page
title: projects
description: Code, tools, and other things I've built
permalink: /projects
---

{% assign projects = site.data.projects %}
{% if projects and projects.size > 0 %}
<div class="project-grid">
{% for project in projects %}
  <a class="project-card" href="{{ project.url }}">
    <span class="project-card-head">
      <span class="project-name">{{ project.name }}</span>
      <span class="project-arrow">↗</span>
    </span>
    {% if project.desc %}<span class="project-desc">{{ project.desc }}</span>{% endif %}
    {% if project.role %}<span class="project-role">{{ project.role }}</span>{% endif %}
  </a>
{% endfor %}
</div>
{% else %}
  <p><em>No projects listed yet.</em></p>
{% endif %}
