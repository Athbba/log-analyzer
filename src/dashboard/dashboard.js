/// <reference lib="dom" />
/// <reference lib="dom.iterable" />
// Progressive enhancement only. No HTML injection, evaluation, or network calls.

/** @param {number} start @param {number} end @param {'start'|'end'} edge @param {number} first @param {number} last */
export function constrainWindow(start, end, edge, first, last) {
  start = Math.max(first, Math.min(last, start));
  end = Math.max(first, Math.min(last, end));
  if (start > end) {
    if (edge === 'start') start = end;
    else end = start;
  }
  return [start, end];
}

/** @param {number} value */
const dateValue = (value) => new Date(value).toISOString().slice(0, 23);

function enhance() {
  document.documentElement.classList.add('js');
  const from = document.querySelector('#from');
  const to = document.querySelector('#to');
  const readout = document.querySelector('#range-readout');
  const brush = document.querySelector('.brush');
  if (brush instanceof HTMLElement && from instanceof HTMLInputElement && to instanceof HTMLInputElement) {
    const start = brush.querySelector('.range-start');
    const end = brush.querySelector('.range-end');
    const selection = brush.querySelector('.brush-selection');
    const first = Number(brush.dataset.first), last = Number(brush.dataset.last);
    if (start instanceof HTMLInputElement && end instanceof HTMLInputElement && selection instanceof HTMLElement) {
      /** @param {'start'|'end'} edge @param {boolean} writeDates */
      const update = (edge, writeDates) => {
        const [a, b] = constrainWindow(Number(start.value), Number(end.value), edge, first, last);
        start.value = String(a); end.value = String(b);
        const length = Math.max(1, last - first);
        selection.style.left = `${(a - first) / length * 100}%`;
        selection.style.width = `${(b - a) / length * 100}%`;
        start.setAttribute('aria-valuetext', dateValue(a).replace('T', ' ') + ' server local');
        end.setAttribute('aria-valuetext', dateValue(b).replace('T', ' ') + ' server local');
        if (readout) readout.textContent = `${dateValue(a).slice(0, 19).replace('T', ' ')} – ${dateValue(b).slice(0, 19).replace('T', ' ')}`;
        if (writeDates) { from.value = dateValue(a); to.value = dateValue(b); to.setCustomValidity(''); }
      };
      start.addEventListener('input', () => update('start', true));
      end.addEventListener('input', () => update('end', true));
      from.addEventListener('change', () => { to.setCustomValidity(''); start.value = from.value ? String(Date.parse(from.value + 'Z')) : String(first); update('start', false); });
      to.addEventListener('change', () => { to.setCustomValidity(''); end.value = to.value ? String(Date.parse(to.value + 'Z')) : String(last); update('end', false); });
      update('start', false);
    }
    from.addEventListener('input', () => to.setCustomValidity(''));
    to.addEventListener('input', () => to.setCustomValidity(''));
    from.form?.addEventListener('submit', (event) => {
      to.setCustomValidity(from.value && to.value && from.value > to.value ? 'Window end must be at or after window start.' : '');
      if (!to.reportValidity()) event.preventDefault();
    });
  }

  const status = document.querySelector('#copy-status');
  for (const button of document.querySelectorAll('[data-copy]')) {
    if (!(button instanceof HTMLButtonElement)) continue;
    button.hidden = false;
    button.addEventListener('click', async () => {
      const target = document.getElementById(button.dataset.copy ?? '');
      if (!target) return;
      const text = Array.from(target.querySelectorAll('.log-raw'), (line) => line.textContent ?? '').join('\n') + '\n';
      try {
        await navigator.clipboard.writeText(text);
        button.textContent = 'Copied';
        if (status) status.textContent = 'Visible raw log lines copied. Line numbers excluded.';
        setTimeout(() => { button.textContent = 'Copy raw'; }, 1800);
      } catch {
        const details = target.closest('details');
        if (details) details.open = true;
        target.focus();
        button.textContent = 'Select to copy';
        if (status) status.textContent = 'Clipboard unavailable. Select the evidence and use your keyboard copy command.';
      }
    });
  }

  const tooltip = document.querySelector('#chart-tooltip');
  if (!(tooltip instanceof HTMLElement)) return;
  const hide = () => { tooltip.hidden = true; };
  for (const link of document.querySelectorAll('[data-tooltip]')) {
    /** @param {number} x @param {number} y */
    const show = (x, y) => {
      tooltip.textContent = link.getAttribute('data-tooltip');
      tooltip.hidden = false;
      const box = tooltip.getBoundingClientRect();
      tooltip.style.left = `${Math.max(8, Math.min(x + 12, window.innerWidth - box.width - 8))}px`;
      tooltip.style.top = `${Math.max(8, Math.min(y + 16, window.innerHeight - box.height - 8))}px`;
    };
    link.addEventListener('pointermove', (event) => { if (event instanceof PointerEvent) show(event.clientX, event.clientY); });
    link.addEventListener('focus', () => { const r = link.getBoundingClientRect(); show(r.left, r.bottom); });
    link.addEventListener('pointerleave', hide);
    link.addEventListener('blur', hide);
  }
  document.addEventListener('keydown', (event) => { if (event.key === 'Escape') hide(); });
  window.addEventListener('scroll', hide, true);
}

if (typeof document !== 'undefined') enhance();
