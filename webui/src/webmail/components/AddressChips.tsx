// 收件人芯片输入（To / Cc / Bcc）—— 契约 §5.4：
// 回车/逗号分隔、格式校验、去重、可删除；粘贴多地址也可用。
import { useId, useRef, useState, type ClipboardEvent, type KeyboardEvent } from "react";
import { parseAddresses, type ParsedAddresses } from "../lib/address";
import { useMailPrefs } from "../store/prefs";
import { IconX } from "./icons";

const SEPARATOR_KEYS = new Set(["Enter", "Tab", ",", ";", "，", "；"]);

export function AddressChips({
  label,
  addresses,
  onChange,
  placeholder,
  autoFocus = false,
  inputId,
  variant = "to",
}: {
  label: string;
  addresses: string[];
  onChange: (next: string[]) => void;
  placeholder?: string;
  autoFocus?: boolean;
  inputId?: string;
  variant?: "to" | "cc" | "bcc";
}) {
  const { t } = useMailPrefs();
  const [draft, setDraft] = useState("");
  const [error, setError] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);
  const generatedId = useId();
  const id = inputId ?? `mail-addr-${variant}-${generatedId}`;

  const apply = (raw: string): ParsedAddresses => {
    const parsed = parseAddresses(raw, addresses);
    if (parsed.valid.length) onChange([...addresses, ...parsed.valid]);
    if (parsed.invalid.length) {
      setError(t("recipients_invalid", { list: parsed.invalid.join(", ") }));
    } else {
      setError("");
    }
    setDraft("");
    return parsed;
  };

  const commit = (raw: string) => {
    if (!raw.trim()) {
      setDraft("");
      return;
    }
    apply(raw);
  };

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (SEPARATOR_KEYS.has(e.key)) {
      e.preventDefault();
      commit(draft);
      return;
    }
    if (e.key === "Backspace" && draft === "" && addresses.length > 0) {
      e.preventDefault();
      onChange(addresses.slice(0, -1));
      setError("");
      return;
    }
    if (e.key === "Escape") {
      // 芯片输入的 Esc 只清空草稿，不关闭写信浮层（避免误丢内容）。
      e.stopPropagation();
      setDraft("");
    }
  };

  const onPaste = (e: ClipboardEvent<HTMLInputElement>) => {
    const text = e.clipboardData?.getData("text") ?? "";
    if (/[,;，；\n\t]/.test(text)) {
      e.preventDefault();
      commit(`${draft}${draft ? "," : ""}${text}`);
    }
  };

  return (
    <div className={`mail-field ${error ? "is-invalid" : ""}`}>
      <label className="mail-field-label" htmlFor={id}>
        {label}
      </label>
      <div className="mail-chips" onClick={() => inputRef.current?.focus()}>
        {addresses.map((address) => (
          <span className="mail-chip" key={address} title={address}>
            <span className="mail-chip-text">{address}</span>
            <button
              type="button"
              className="mail-chip-x"
              aria-label={`${t("delete")}: ${address}`}
              onClick={(e) => {
                e.stopPropagation();
                onChange(addresses.filter((a) => a !== address));
                setError("");
              }}
            >
              <IconX size={10} />
            </button>
          </span>
        ))}
        <input
          id={id}
          ref={inputRef}
          className="mail-chip-input"
          value={draft}
          placeholder={addresses.length ? "" : placeholder}
          autoFocus={autoFocus}
          autoComplete="off"
          spellCheck={false}
          onChange={(e) => {
            setDraft(e.target.value);
            if (error) setError("");
          }}
          onKeyDown={onKeyDown}
          onBlur={() => commit(draft)}
          onPaste={onPaste}
        />
      </div>
      {error && (
        <div className="mail-field-error" role="alert">
          {error}
        </div>
      )}
    </div>
  );
}
