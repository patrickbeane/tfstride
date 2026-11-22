(() => {
  const form = document.getElementById("plan-upload");
  if (!form || !window.File || !File.prototype.text) return;

  const maxBytes = Number(form.dataset.maxUploadBytes);
  if (!Number.isFinite(maxBytes) || maxBytes <= 0) return;

  const input = document.getElementById("plan-file");
  const zone = document.getElementById("upload-dropzone");
  const empty = document.getElementById("dropzone-empty");
  const selected = document.getElementById("selected-plan");
  const filename = document.getElementById("plan-filename");
  const filesize = document.getElementById("plan-filesize");
  const fileState = document.getElementById("plan-file-state");
  const remove = document.getElementById("remove-plan");
  const status = document.getElementById("upload-status");
  const error = document.getElementById("upload-error");
  const analyze = document.getElementById("analyze-plan");
  const analyzeLabel = document.getElementById("analyze-label");
  let validationId = 0;
  let ready = false;
  let submitting = false;
  let dragDepth = 0;

  function formatSize(bytes) {
    if (bytes < 1024) return `${bytes} ${bytes === 1 ? "byte" : "bytes"}`;
    const unit = bytes < 1024 * 1024 ? 1024 : 1024 * 1024;
    return `${(bytes / unit).toFixed(1).replace(/\.0$/, "")} ${unit === 1024 ? "KiB" : "MiB"}`;
  }

  function showError(message) {
    ready = false;
    input.setCustomValidity(message);
    input.setAttribute("aria-invalid", "true");
    zone.dataset.invalid = "true";
    fileState.textContent = "File needs attention";
    error.hidden = false;
    error.textContent = message;
    status.textContent = "";
    analyze.disabled = true;
  }

  async function checkSelection() {
    const currentValidation = ++validationId;
    ready = false;
    input.setCustomValidity("");
    input.removeAttribute("aria-invalid");
    delete zone.dataset.invalid;
    error.hidden = true;
    error.textContent = "";
    status.textContent = "";

    const file = input.files[0];
    empty.hidden = Boolean(file);
    selected.hidden = !file;
    remove.hidden = !file;
    filename.textContent = file?.name || "";
    filesize.textContent = file ? formatSize(file.size) : "";
    fileState.textContent = "";
    analyze.disabled = Boolean(file);
    if (!file) return;

    if (file.size === 0) {
      showError("This file is empty. Choose a non-empty Terraform plan JSON file.");
      return;
    }
    if (file.size > maxBytes) {
      showError(`This file exceeds the ${formatSize(maxBytes)} limit. Choose a smaller plan.`);
      return;
    }

    fileState.textContent = "Checking JSON…";
    status.textContent = `Checking ${file.name}, ${formatSize(file.size)}.`;
    let contents;
    try {
      contents = await file.text();
    } catch {
      if (currentValidation === validationId) showError("This file could not be read. Choose it again.");
      return;
    }
    // A removed or replaced file must never overwrite the current selection.
    if (currentValidation !== validationId) return;
    try {
      JSON.parse(contents);
    } catch {
      showError("This file is not valid JSON. Export it with terraform show -json and try again.");
      return;
    }

    // Check JSON syntax only. Terraform validation and all analysis stay on the server.
    ready = true;
    fileState.textContent = "JSON checked · Ready to analyze";
    status.textContent = `${file.name}, ${formatSize(file.size)}. JSON syntax checked. Ready to analyze.`;
    analyze.disabled = false;
  }

  function clearDrag() {
    dragDepth = 0;
    zone.classList.remove("is-dragging");
  }

  function isFileDrag(event) {
    return event.dataTransfer && Array.from(event.dataTransfer.types).includes("Files");
  }

  input.addEventListener("change", () => {
    if (!submitting) void checkSelection();
  });
  input.addEventListener("click", event => {
    if (submitting) event.preventDefault();
  });
  input.addEventListener("invalid", () => {
    if (!input.files.length) showError("Choose a Terraform plan JSON file to analyze.");
  });

  remove.addEventListener("click", () => {
    if (submitting) return;
    input.value = "";
    void checkSelection();
    status.textContent = "File removed. Choose another Terraform plan JSON file.";
    input.focus();
  });

  zone.addEventListener("dragenter", event => {
    if (!isFileDrag(event)) return;
    event.preventDefault();
    if (!submitting) {
      dragDepth += 1;
      zone.classList.add("is-dragging");
    }
  });
  zone.addEventListener("dragover", event => {
    if (!isFileDrag(event)) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = submitting ? "none" : "copy";
  });
  zone.addEventListener("dragleave", event => {
    if (!isFileDrag(event)) return;
    dragDepth = Math.max(0, dragDepth - 1);
    if (!dragDepth) clearDrag();
  });
  zone.addEventListener("drop", event => {
    if (!isFileDrag(event)) return;
    event.preventDefault();
    clearDrag();
    if (submitting) return;

    const files = event.dataTransfer.files;
    if (files.length !== 1) {
      input.value = "";
      void checkSelection();
      showError("Choose one Terraform plan JSON file at a time.");
      input.focus();
      return;
    }
    try {
      input.files = files;
    } catch {
      input.value = "";
      void checkSelection();
      showError("Your browser could not attach the dropped file. Use browse files to choose it.");
      input.focus();
      return;
    }
    void checkSelection();
    input.focus();
  });

  // Avoid navigating away from the workspace when a file misses the drop zone.
  document.addEventListener("dragover", event => {
    if (isFileDrag(event)) event.preventDefault();
  });
  document.addEventListener("drop", event => {
    if (isFileDrag(event)) {
      event.preventDefault();
      clearDrag();
    }
  });
  document.addEventListener("dragend", clearDrag);

  form.addEventListener("submit", event => {
    if (submitting || !ready) {
      event.preventDefault();
      if (!submitting) input.reportValidity();
      return;
    }
    submitting = true;
    clearDrag();
    form.setAttribute("aria-busy", "true");
    analyze.disabled = true;
    remove.disabled = true;
    analyzeLabel.textContent = "Analyzing plan…";
    status.textContent = `Analyzing ${input.files[0].name}.`;
    // Keep the native file input enabled so it remains in the multipart request.
  });

  window.addEventListener("pageshow", event => {
    if (!event.persisted) return;
    submitting = false;
    form.removeAttribute("aria-busy");
    remove.disabled = false;
    analyzeLabel.textContent = "Analyze plan";
    void checkSelection();
  });

  form.dataset.enhanced = "true";
  void checkSelection();
  document.getElementById("server-error")?.focus();
})();
