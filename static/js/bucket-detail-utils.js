window.BucketDetailUtils = (function() {
  'use strict';

  function setupJsonAutoIndent(textarea) {
    if (!textarea) return;

    textarea.addEventListener('keydown', function(e) {
      if (e.key === 'Enter') {
        e.preventDefault();

        const start = this.selectionStart;
        const end = this.selectionEnd;
        const value = this.value;

        const lineStart = value.lastIndexOf('\n', start - 1) + 1;
        const currentLine = value.substring(lineStart, start);

        const indentMatch = currentLine.match(/^(\s*)/);
        let indent = indentMatch ? indentMatch[1] : '';

        const trimmedLine = currentLine.trim();
        const lastChar = trimmedLine.slice(-1);

        let newIndent = indent;
        let insertAfter = '';

        if (lastChar === '{' || lastChar === '[') {
          newIndent = indent + '  ';

          const charAfterCursor = value.substring(start, start + 1).trim();
          if ((lastChar === '{' && charAfterCursor === '}') ||
              (lastChar === '[' && charAfterCursor === ']')) {
            insertAfter = '\n' + indent;
          }
        } else if (lastChar === ',' || lastChar === ':') {
          newIndent = indent;
        }

        const insertion = '\n' + newIndent + insertAfter;
        const newValue = value.substring(0, start) + insertion + value.substring(end);

        this.value = newValue;

        const newCursorPos = start + 1 + newIndent.length;
        this.selectionStart = this.selectionEnd = newCursorPos;

        this.dispatchEvent(new Event('input', { bubbles: true }));
      }

      if (e.key === 'Tab') {
        e.preventDefault();
        const start = this.selectionStart;
        const end = this.selectionEnd;

        if (e.shiftKey) {
          const lineStart = this.value.lastIndexOf('\n', start - 1) + 1;
          const lineContent = this.value.substring(lineStart, start);
          if (lineContent.startsWith('  ')) {
            this.value = this.value.substring(0, lineStart) +
                         this.value.substring(lineStart + 2);
            this.selectionStart = this.selectionEnd = Math.max(lineStart, start - 2);
          }
        } else {
          this.value = this.value.substring(0, start) + '  ' + this.value.substring(end);
          this.selectionStart = this.selectionEnd = start + 2;
        }

        this.dispatchEvent(new Event('input', { bubbles: true }));
      }
    });
  }

  function formatBytes(bytes) {
    if (!Number.isFinite(bytes)) return `${bytes} bytes`;
    const units = ['bytes', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    let size = bytes;
    while (size >= 1024 && i < units.length - 1) {
      size /= 1024;
      i++;
    }
    return `${size.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
  }

  function escapeHtml(value) {
    if (value === null || value === undefined) return '';
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function fallbackCopy(text) {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.left = '-9999px';
    textArea.style.top = '-9999px';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    let success = false;
    try {
      success = document.execCommand('copy');
    } catch {
      success = false;
    }
    document.body.removeChild(textArea);
    return success;
  }

  return {
    setupJsonAutoIndent: setupJsonAutoIndent,
    formatBytes: formatBytes,
    escapeHtml: escapeHtml,
    fallbackCopy: fallbackCopy
  };
})();
