// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// Copy buttons, the manual's option finder and current-section highlight.
// Every page works without this file.

document.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-copy]");
  if (!button) return;
  try {
    await navigator.clipboard.writeText(button.dataset.copy);
  } catch {
    return;
  }
  const label = button.textContent;
  const isHash = button.classList.contains("hash");
  button.classList.add("done");
  if (!isHash) button.textContent = "Copied";
  setTimeout(() => {
    button.classList.remove("done");
    if (!isHash) button.textContent = label;
  }, 1400);
});

// Home stage: switch between the static output and the terminal recordings.
// Each GIF is fetched only when asked for.
const stage = document.querySelector(".stage");
if (stage) {
  const sw = stage.querySelector(".switch");
  const modes = [...sw.querySelectorAll("button[data-show]")].map((b) => b.dataset.show);
  sw.hidden = false;
  sw.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-show]");
    if (!button) return;
    const mode = button.dataset.show;
    for (const b of sw.querySelectorAll("button")) b.setAttribute("aria-pressed", String(b === button));
    const shot = stage.querySelector(`.shot-${mode}`);
    for (const el of shot.querySelectorAll("[data-srcset]")) { el.srcset = el.dataset.srcset; el.removeAttribute("data-srcset"); }
    for (const el of shot.querySelectorAll("[data-src]")) { el.src = el.dataset.src; el.removeAttribute("data-src"); }
    for (const name of modes) {
      stage.querySelector(`.shot-${name}`).hidden = name !== mode;
      stage.querySelector(`.caption-${name}`).hidden = name !== mode;
    }
  });
}

const text = (node) => node.textContent.replace(/\s+/g, " ").trim();

// Option finder: every tagged term (options, properties, fields) and heading in the page.
const side = document.querySelector(".man-side");
const manual = document.querySelector(".manual-text");
if (side && manual) {
  const entries = [];
  let section = "";
  for (const node of manual.querySelectorAll("h2.Sh, h3.Ss, dl > dt[id]")) {
    if (node.tagName !== "DT") {
      section = text(node);
      entries.push({ id: node.id, label: section.charAt(0) + section.slice(1).toLowerCase(), context: "Section" });
    } else {
      entries.push({ id: node.id, label: text(node), context: section });
    }
  }

  const finder = document.createElement("div");
  finder.className = "finder";
  finder.innerHTML =
    '<input type="search" placeholder="Find an option or field" autocomplete="off" spellcheck="false"' +
    ' role="combobox" aria-expanded="false" aria-controls="finder-results" aria-label="Find in this manual">' +
    '<kbd aria-hidden="true">/</kbd><ul id="finder-results" role="listbox"></ul>';
  side.querySelector(".man-switch").after(finder);
  const input = finder.querySelector("input");
  const list = finder.querySelector("ul");
  let results = [];
  let selected = 0;

  const score = (entry, query) => {
    const label = entry.label.toLowerCase();
    const bare = label.replace(/^-+/, "");
    if (bare.startsWith(query) || label.startsWith(query)) return 0;
    if (label.includes(query)) return 1;
    if (entry.context.toLowerCase().includes(query)) return 2;
    return -1;
  };

  const render = () => {
    const query = input.value.trim().toLowerCase();
    results = query
      ? entries.map((e) => [score(e, query), e]).filter(([s]) => s >= 0)
          .sort((a, b) => a[0] - b[0]).slice(0, 12).map(([, e]) => e)
      : [];
    selected = 0;
    list.replaceChildren(...results.map((e, i) => {
      const li = document.createElement("li");
      const a = document.createElement("a");
      a.href = "#" + e.id;
      a.setAttribute("role", "option");
      a.setAttribute("aria-selected", String(i === selected));
      a.textContent = e.label;
      const small = document.createElement("small");
      small.textContent = e.context;
      a.append(small);
      li.append(a);
      return li;
    }));
    if (query && !results.length) {
      const li = document.createElement("li");
      li.className = "none";
      li.textContent = "No match in this page";
      list.append(li);
    }
    input.setAttribute("aria-expanded", String(Boolean(query)));
  };

  const choose = (i) => {
    const entry = results[i];
    if (!entry) return;
    location.hash = entry.id;
    input.value = "";
    render();
    input.blur();
  };

  input.addEventListener("input", render);
  input.addEventListener("keydown", (event) => {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      if (!results.length) return;
      selected = (selected + (event.key === "ArrowDown" ? 1 : results.length - 1)) % results.length;
      list.querySelectorAll("a").forEach((a, i) => a.setAttribute("aria-selected", String(i === selected)));
      const item = list.querySelectorAll("a")[selected];
      if (item.offsetTop < list.scrollTop || item.offsetTop + item.offsetHeight > list.scrollTop + list.clientHeight)
        list.scrollTop = item.offsetTop - list.clientHeight / 2;
    } else if (event.key === "Enter") {
      event.preventDefault();
      choose(selected);
    } else if (event.key === "Escape") {
      input.value = "";
      render();
      input.blur();
    }
  });
  list.addEventListener("click", () => {
    input.value = "";
    render();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key !== "/" || event.metaKey || event.ctrlKey || event.altKey) return;
    if (event.target.closest("input, textarea, [contenteditable]")) return;
    event.preventDefault();
    input.focus();
  });
}

// Contents: highlight the section being read.
const toc = document.querySelector(".toc");
if (toc) {
  if (matchMedia("(max-width: 960px)").matches) toc.removeAttribute("open");
  const links = new Map([...toc.querySelectorAll("a")].map((a) => [a.hash.slice(1), a]));
  const headings = [...links.keys()].map((id) => document.getElementById(id)).filter(Boolean);
  let current = null;
  const update = () => {
    let active = headings[0];
    for (const h of headings) if (h.getBoundingClientRect().top < 120) active = h;
    if (active === current) return;
    links.get(current?.id)?.classList.remove("active");
    current = active;
    const link = links.get(active.id);
    link?.classList.add("active");
    // Scroll only the sidebar; scrollIntoView would also move the page.
    const box = side?.scrollHeight > side?.clientHeight ? side : null;
    if (link && box) {
      const top = link.offsetTop; // .man-side is sticky, so it is the offset parent
      if (top < box.scrollTop || top > box.scrollTop + box.clientHeight - 40) box.scrollTop = top - box.clientHeight / 3;
    }
  };
  addEventListener("scroll", update, { passive: true });
  addEventListener("hashchange", update);
  addEventListener("load", update);
  update();
}

// Hairline under the header only once the page has moved.
const markScrolled = () => document.body.classList.toggle("scrolled", scrollY > 8);
addEventListener("scroll", markScrolled, { passive: true });
markScrolled();
