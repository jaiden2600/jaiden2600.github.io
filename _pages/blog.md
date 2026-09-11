---
layout: page
title: blog
description: Technical writeups from security research
permalink: /blog
---

<ul class="blog-posts">
{% for post in site.posts %}
  <li>
    <span><i><time datetime="{{ post.date | date_to_xmlschema }}">{{ post.date | date: "%b %-d, %Y" }}</time></i></span>
    <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
  </li>
{% endfor %}
{% if site.posts.size == 0 %}
  <li><span></span><em>No posts yet.</em></li>
{% endif %}
</ul>
