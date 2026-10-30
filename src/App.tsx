import { createPortal } from "react-dom";
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from "react";
import {
  ArrowDown,
  ArrowDownToLine,
  ArrowLeft,
  ArrowRight,
  Check,
  CheckCheck,
  ChevronDown,
  CircleHelp,
  Clock3,
  Cloud,
  File,
  FileText,
  Fingerprint,
  Folder,
  FolderClosed,
  Grid2X2,
  HardDrive,
  Image,
  KeyRound,
  LayoutGrid,
  List,
  LoaderCircle,
  LockKeyhole,
  Menu,
  MoreHorizontal,
  Plus,
  Search,
  Settings2,
  ShieldCheck,
  Sparkles,
  Star,
  StickyNote,
  Trash2,
  Upload,
  X,
  Eye,
  EyeOff,
  RotateCcw,
  CheckCircle2,
  Circle,
} from "lucide-react";
import { demoItems, formatBytes, type DisplayItem } from "./demo";
import { unlockVault, type VaultConfig } from "./lib/crypto";
import {
  enrollPasskey,
  isFirebaseConfigured,
  isEmulatorMode,
  isVaultBackendReady,
  signInWithPasskey,
  signOutVault,
  getVaultSessionDeadline,
  getVaultSessionLifetimeMinutes,
  getVaultUserId,
  isAuthenticationFailure,
  validateVaultSession,
} from "./lib/firebase";
import {
  downloadVaultFile,
  getVaultConfig,
  listVaultItems,
  permanentlyDeleteVaultItem,
  saveVaultConfig,
  saveVaultNote,
  updateVaultItem,
  uploadVaultFile,
  MAX_FILE_SIZE,
} from "./lib/vault";
import { lockVaultState, sessionDeadline, type VaultState } from "./lib/vaultState";
import { clearPlaintext, createPlaintextUrl, revokePlaintextUrl } from "./lib/plaintext";
import { useVaultPolicy } from "./lib/useVaultPolicy";
import { createKeyRecord } from './lib/keys';
import SecurityCenter from './components/SecurityCenter';
import Recovery from './components/Recovery';
import SecuritySettings from "./components/SecuritySettings";
import ItemMenu from "./components/ItemMenu";
import Modal from "./components/Modal";
import Preview from "./components/Preview";

type Section = "My vault" | "Recent" | "Favorites" | "Trash" | "Security";
type Category = "all" | "photo" | "document" | "note";
type ModalKind = "upload" | "note" | "collection" | "setup" | "help" | null;
const isDemoPreview =
  new URLSearchParams(window.location.search).get("demo") === "1" || !isFirebaseConfigured;
const kindNames = { photo: "Photos", document: "Documents", note: "Notes", other: "Other" };
const errorMessage = (error: unknown) =>
  error instanceof Error
    ? error.message.replace(/^Firebase: /, "")
    : "Something went wrong. Please try again.";
const prettyDate = (time: number) =>
  new Date(time).toLocaleDateString(undefined, { month: "short", day: "numeric" });

function Brand({ light = false }: { light?: boolean }) {
  return (
    <div className={`brand ${light ? "brand-light" : ""}`}>
      <span className="brand-mark">
        <svg viewBox="0 0 36 36" fill="none">
          <path
            d="M8 29V17a10 10 0 0 1 20 0v12M14 29V18a4 4 0 0 1 8 0v11"
            stroke="currentColor"
            strokeWidth="3.2"
            strokeLinecap="round"
          />
        </svg>
      </span>
      <span>
        haven<span className="brand-period">.</span>
      </span>
    </div>
  );
}

function ArchIllustration() {
  return (
    <div className="arch-scene" aria-hidden="true">
      <div className="orbit orbit-one" />
      <div className="orbit orbit-two" />
      <div className="orbit orbit-three" />
      <span className="sparkle s-one">✧</span>
      <span className="sparkle s-two">+</span>
      <div className="arch-base" />
      <div className="arch-body">
        <div className="arch-inset">
          <div className="keyhole">
            <i />
          </div>
        </div>
        <div className="arch-shine" />
      </div>
      <div className="floating-seal">
        <ShieldCheck size={22} />
      </div>
    </div>
  );
}

export default function App() {
  const [vaultState, setVaultState] = useState<VaultState>(isDemoPreview ? { status: "demo" } : { status: "signed-out" });
  const stateRef = useRef(vaultState);
  const transition = useCallback((next: VaultState) => {
    stateRef.current = next;
    setVaultState(next);
  }, []);
  const demo = vaultState.status === "demo";
  const screen = vaultState.status === "signed-out" ? "login"
    : vaultState.status === "locked" ? (vaultState.config === null ? "create" : "unlock") : "vault";
  const vaultKey = vaultState.status === "unlocked" ? vaultState.key : null;
  const deadline = sessionDeadline(vaultState);
  const [items, setItems] = useState<DisplayItem[]>(isDemoPreview ? demoItems : []);
  const [section, setSection] = useState<Section>("My vault");
  const [category, setCategory] = useState<Category>("all");
  const [collection, setCollection] = useState("");
  const [collections, setCollections] = useState(["Personal", "Travel", "Work"]);
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState("newest");
  const [view, setView] = useState<"grid" | "list">("grid");
  const [modal, setModal] = useState<ModalKind>(null);
  const [previewId, setPreviewId] = useState<string | null>(null);
  const [menuId, setMenuId] = useState<string | null>(null);
  const [deleteItem, setDeleteItem] = useState<DisplayItem | null>(null);
  const [mobileNav, setMobileNav] = useState(false);
  const [busy, setBusy] = useState(false);
  const [recoveryActive, setRecoveryActive] = useState(false);
  const [enrollmentStep, setEnrollmentStep] = useState<"confirm" | "registering" | null>(null);
  const enrollmentAction = useRef<{ start: () => void; cancel: () => void } | null>(null);
  const [progress, setProgress] = useState("");
  const [toast, setToast] = useState("");
  const [error, setError] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [showPassphrase, setShowPassphrase] = useState(false);
  const [acknowledged, setAcknowledged] = useState(false);
  const [noteTitle, setNoteTitle] = useState("");
  const [noteText, setNoteText] = useState("");
  const [newCollection, setNewCollection] = useState("");
  const [uploadCollection, setUploadCollection] = useState("Personal");
  const [dragging, setDragging] = useState(false);
  const authenticationGeneration = useRef(0);
  const generationRef = useRef(0);
  const searchRef = useRef<HTMLInputElement>(null);
  const uploadRef = useRef<HTMLInputElement>(null);

  const notify = useCallback((message: string) => setToast(message), []);
  useEffect(() => {
    if (toast) {
      const timeout = setTimeout(() => setToast(""), 4500);
      return () => clearTimeout(timeout);
    }
  }, [toast]);
  const clearSensitiveState = useCallback(() => {
    generationRef.current++;
    setRecoveryActive(false);
    clearPlaintext();
    setItems([]);
    setPreviewId(null);
    setModal(null);
    setDeleteItem(null);
    setMenuId(null);
    setNoteText("");
    setNoteTitle("");
    setPassphrase("");
    setConfirmPassphrase("");
    setSearch("");
    setCollections(["Personal", "Travel", "Work"]);
    setCollection("");
    setNewCollection("");
    setUploadCollection("Personal");
    setShowPassphrase(false);
    setAcknowledged(false);
    setProgress("");
    setToast("");
    setDragging(false);
    setMobileNav(false);
    setSection("My vault");
    setCategory("all");
    if (uploadRef.current) uploadRef.current.value = "";
    setBusy(false);
    setError("");
  }, []);
  const endSession = useCallback((message = "") => {
    authenticationGeneration.current++;
    enrollmentAction.current?.cancel();
    setEnrollmentStep(null);
    clearSensitiveState();
    transition({ status: "signed-out" });
    void signOutVault().then(({ revoked }) => {
      if (!revoked && stateRef.current.status === "signed-out") {
        notify("Signed out on this device. Remote revocation failed; the server session remains valid until its enforced expiry.");
      }
    });
    if (message) notify(message);
  }, [clearSensitiveState, transition, notify]);
  const lock = useCallback((message = "") => {
    // Locking invalidates encryption work only, never a passkey ceremony/session.
    if (stateRef.current.status === "signed-out") {
      clearSensitiveState();
      if (message) notify("Recovery was cleared. Start again with your saved kit.");
      return;
    }
    clearSensitiveState();
    transition(lockVaultState(stateRef.current));
    if (message) notify(message);
  }, [clearSensitiveState, transition, notify]);
  const handleVaultError = useCallback((err: unknown) => {
    if (isAuthenticationFailure(err)) endSession("Your secure session ended. Sign in again.");
    else setError(errorMessage(err));
  }, [endSession]);
  const workIsCurrent = (generation: number, requireUnlocked = true) => {
    if (generation !== generationRef.current || !policy.evaluate()) return false;
    if (stateRef.current.status === "demo") return true;
    if (requireUnlocked && stateRef.current.status !== "unlocked") return false;
    getVaultUserId(); // Check wall-clock expiry even after browser suspension.
    return true;
  };

  const policy = useVaultPolicy({
    expiresAt: deadline,
    unlocked: vaultState.status === "unlocked" || demo || recoveryActive,
    authenticated: !!deadline,
    lock, expire: endSession,
    conceal: (background) => {
      clearPlaintext();
      setPreviewId(null);
      // Cancel ordinary unlock drafts immediately. An open recovery workflow
      // follows the configured grace/idle policy, including native UI hiding.
      if (background && stateRef.current.status === "locked" && !recoveryActive) clearSensitiveState();
    },
    validate: async () => {
      if (stateRef.current.status !== "locked" && stateRef.current.status !== "unlocked") return;
      const current = authenticationGeneration.current;
      await validateVaultSession();
      if (current !== authenticationGeneration.current) return;
      const state = stateRef.current;
      if (state.status === "locked" || state.status === "unlocked") {
        transition({ ...state, expiresAt: Math.min(state.expiresAt, getVaultSessionDeadline()) });
      }
    },
    failure: handleVaultError,
  });
  const canRevealContent = useCallback(() => policy.evaluate() &&
    document.visibilityState === "visible" && !document.documentElement.dataset.havenConcealed,
  [policy.evaluate]);
  const canUseVault = () => canRevealContent() &&
    (stateRef.current.status === "unlocked" || stateRef.current.status === "demo");
  const recoveryGeneration = generationRef.current;
  const privacyScreen = createPortal(<div className="privacy-screen" role="status" aria-live="polite" aria-hidden={!policy.concealed}>
    <strong>Haven is concealed</strong>
    <span>Your content is hidden while Haven is inactive. Return here to continue.</span>
    <div className="privacy-actions">
      <button className="button secondary" disabled={vaultState.status === "signed-out" && !recoveryActive} onClick={() => lock()}>Lock now</button>
      <button className="button secondary" onClick={() => endSession()}>Sign out now</button>
    </div>
  </div>, document.body);
  const securitySettings = <SecuritySettings preferences={policy.preferences}
    onChange={policy.updatePreferences} storageFailed={policy.storageFailed}
    lifetimeMinutes={deadline ? getVaultSessionLifetimeMinutes() : null} />;
  useEffect(() => {
    const shortcut = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        searchRef.current?.focus();
      }
      if ((event.metaKey || event.ctrlKey) && event.shiftKey && event.key.toLowerCase() === "l") {
        event.preventDefault();
        lock("Vault locked.");
      }
      if (event.key === "Escape") setMenuId(null);
    };
    window.addEventListener("keydown", shortcut);
    return () => window.removeEventListener("keydown", shortcut);
  }, [lock]);
  useEffect(() => {
    if (!menuId) return;
    const close = () => setMenuId(null);
    window.addEventListener("click", close);
    return () => window.removeEventListener("click", close);
  }, [menuId]);

  const liveItems = useMemo(() => items.filter((item) => !item.trashed), [items]);
  const totalSize = liveItems.reduce((total, item) => total + item.size, 0);
  const visibleItems = useMemo(() => {
    let result = items.filter((item) => (section === "Trash" ? item.trashed : !item.trashed));
    if (section === "Favorites") result = result.filter((item) => item.favorite);
    if (collection) result = result.filter((item) => item.collection === collection);
    if (category !== "all") result = result.filter((item) => item.kind === category);
    if (search.trim())
      result = result.filter((item) =>
        `${item.name} ${item.collection} ${item.text || ""}`
          .toLowerCase()
          .includes(search.toLowerCase().trim()),
      );
    return result
      .sort((a, b) =>
        sort === "name"
          ? a.name.localeCompare(b.name)
          : sort === "size"
            ? b.size - a.size
            : b.createdAt - a.createdAt,
      )
      .slice(0, section === "Recent" ? 12 : undefined);
  }, [items, section, collection, category, search, sort]);
  const preview = items.find((item) => item.id === previewId);
  const allCollections = [
    ...new Set([...collections, ...items.map((item) => item.collection)]),
  ].filter(Boolean);

  const openSection = (next: Section, folder = "") => {
    setSection(next);
    setCollection(folder);
    setCategory("all");
    setSearch("");
    setMobileNav(false);
  };
  const openModal = (kind: ModalKind) => {
    setModal(kind);
    setError("");
    setProgress("");
  };
  const enterDemo = () => {
    endSession();
    transition({ status: "demo" });
    setItems(demoItems.map(item => ({ ...item })));
  };
  const authenticate = async (enroll: boolean) => {
    if (!isVaultBackendReady) {
      setError("Secure storage is awaiting activation. Enable Firebase billing and Storage, then deploy the included security functions and rules. You can explore the sample vault below.");
      return;
    }
    const current = ++authenticationGeneration.current;
    const work = generationRef.current;
    setBusy(true);
    setError("");
    try {
      if (enroll) await enrollPasskey((createPasskey) => new Promise((resolve, reject) => {
        if (current !== authenticationGeneration.current) {
          reject(new Error("Setup was cancelled. Please start again."));
          return;
        }
        const clearRequest = () => {
          clearTimeout(timeout);
          enrollmentAction.current = null;
        };
        const timeout = setTimeout(() => {
          clearRequest();
          reject(new Error("This setup request expired. Select Set up my private vault to start again."));
        }, 4 * 60_000);
        enrollmentAction.current = {
          start: () => {
            clearRequest();
            setEnrollmentStep("registering");
            // Invoke WebAuthn in this click handler, with no intervening network
            // request or automatic prompt following the Google popup.
            try { resolve(createPasskey()); } catch (err) { reject(err); }
          },
          cancel: () => {
            clearRequest();
            reject(new Error("Setup was cancelled. Please start again."));
          },
        };
        setEnrollmentStep("confirm");
      }));
      else await signInWithPasskey();
      if (current !== authenticationGeneration.current) return;
      const expiresAt = getVaultSessionDeadline();
      transition({ status: "locked", expiresAt, config: undefined });
      const config = await getVaultConfig();
      if (current !== authenticationGeneration.current) return;
      getVaultUserId();
      transition({ status: "locked", expiresAt, config });
      setPassphrase("");
      setConfirmPassphrase("");
    } catch (err) {
      if (current === authenticationGeneration.current) {
        if (isAuthenticationFailure(err)) { handleVaultError(err); return; }
        const message = errorMessage(err);
        setError(
          message.includes("internal") ||
            message.includes("not-found") ||
            message.includes("Failed to fetch")
            ? "The Firebase security service is not available yet. Deploy the included functions and rules to activate your vault."
            : message,
        );
      }
    } finally {
      if (current === authenticationGeneration.current) {
        if (work === generationRef.current) setBusy(false);
        setEnrollmentStep(null);
      }
    }
  };
  const decrypt = async (event: FormEvent) => {
    event.preventDefault();
    const state = stateRef.current;
    if (state.status !== "locked" || busy) return;
    const current = generationRef.current;
    setError("");
    if (state.config === null && (passphrase !== confirmPassphrase || !acknowledged)) {
      setError("Make sure your passphrases match and confirm that you have saved it securely.");
      return;
    }
    setBusy(true);
    const secret = passphrase;
    setPassphrase("");
    setConfirmPassphrase("");
    try {
      await validateVaultSession();
      if (!workIsCurrent(current, false) || document.visibilityState !== "visible" || document.documentElement.dataset.havenConcealed) return;
      const config = await getVaultConfig();
      if (!workIsCurrent(current, false)) return;
      if (config === null && state.config === undefined) {
        transition({ status: "locked", expiresAt: state.expiresAt, config: null });
        return;
      }
      let key: CryptoKey;
      let encryptionConfig: VaultConfig;
      if (config === null) {
        const created = await createKeyRecord(secret);
        if (!workIsCurrent(current, false)) return;
        await saveVaultConfig(created.config);
        key = created.key;
        encryptionConfig = created.config;
      } else {
        encryptionConfig = config;
        key = await unlockVault(secret, config);
      }
      if (!workIsCurrent(current, false)) return;
      // Keep the saved config if loading fails or a later unlock is needed.
      transition({ status: "locked", expiresAt: state.expiresAt, config: encryptionConfig });
      const loaded = await listVaultItems(key);
      await validateVaultSession();
      if (!workIsCurrent(current, false) || document.visibilityState !== "visible" || document.documentElement.dataset.havenConcealed) return;
      transition({ status: "unlocked", expiresAt: getVaultSessionDeadline(), config: encryptionConfig, key });
      setItems(loaded);
      setSection("My vault");
      setCategory("all");
      setCollection("");
      notify("Welcome to your private space.");
    } catch (err) {
      if (current === generationRef.current) handleVaultError(err);
    } finally {
      if (current === generationRef.current) setBusy(false);
    }
  };
  const changeItem = async (item: DisplayItem, changes: Partial<DisplayItem>) => {
    if (!canUseVault()) return;
    const next = { ...item, ...changes, updatedAt: Date.now() };
    const current = generationRef.current;
    try {
      if (!demo) {
        if (!vaultKey) throw new Error("Unlock the vault first.");
        await updateVaultItem(vaultKey, next);
      }
      if (!workIsCurrent(current)) return;
      setItems((values) => values.map((value) => (value.id === item.id ? next : value)));
      if ("trashed" in changes)
        notify(
          changes.trashed
            ? "Moved to trash. You can restore it anytime."
            : "File restored to your vault.",
        );
    } catch (err) {
      if (current === generationRef.current) handleVaultError(err);
    }
    if (current === generationRef.current) setMenuId(null);
  };
  const upload = async (files: FileList | File[]) => {
    if (!canUseVault()) return;
    if (demo) {
      openModal("setup");
      return;
    }
    if (!vaultKey) return;
    const fileList = Array.from(files);
    if (!fileList.length) return;
    if (fileList.some((file) => file.size > MAX_FILE_SIZE)) {
      setError("Each file must be 50 MB or smaller.");
      return;
    }
    const current = generationRef.current;
    const key = vaultKey;
    setBusy(true);
    setError("");
    let done = 0;
    try {
      for (const file of fileList) {
        if (!workIsCurrent(current)) return;
        setProgress(`Encrypting and uploading ${++done} of ${fileList.length}…`);
        const item = await uploadVaultFile(key, file, uploadCollection);
        if (!workIsCurrent(current)) return;
        setItems((values) => [item, ...values]);
      }
      setModal(null);
      notify(
        `${fileList.length === 1 ? "File" : `${fileList.length} files`} encrypted and saved to your vault.`,
      );
    } catch (err) {
      if (current === generationRef.current) handleVaultError(err);
    } finally {
      if (current === generationRef.current) {
        setBusy(false);
        setProgress("");
      }
    }
  };
  const saveNote = async (event: FormEvent) => {
    event.preventDefault();
    if (!canUseVault()) return;
    if (demo) {
      openModal("setup");
      return;
    }
    if (!vaultKey || !noteTitle.trim()) return;
    const current = generationRef.current;
    setBusy(true);
    setError("");
    try {
      const item = await saveVaultNote(
        vaultKey,
        noteTitle.trim(),
        noteText,
        uploadCollection,
      );
      if (!workIsCurrent(current)) return;
      setItems((values) => [item, ...values]);
      setModal(null);
      setNoteText("");
      setNoteTitle("");
      notify("Note encrypted and saved.");
    } catch (err) {
      if (current === generationRef.current) handleVaultError(err);
    } finally {
      if (current === generationRef.current) setBusy(false);
    }
  };
  const download = async (item: DisplayItem) => {
    if (!canUseVault()) return;
    const current = generationRef.current;
    try {
      let blob: Blob;
      if (demo) {
        if (item.demoUrl) blob = await (await fetch(item.demoUrl)).blob();
        else if (item.kind === "note") blob = new Blob([item.text || ""], { type: "text/plain" });
        else {
          notify(
            "This is a sample document. Your uploaded PDFs will be available to preview and download.",
          );
          return;
        }
      } else {
        if (!vaultKey) return;
        blob =
          item.kind === "note"
            ? new Blob([item.text || ""], { type: "text/plain" })
            : await downloadVaultFile(vaultKey, item);
      }
      if (!workIsCurrent(current)) return;
      if (document.visibilityState !== "visible" || document.documentElement.dataset.havenConcealed) return;
      const url = createPlaintextUrl(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = item.kind === "note" ? `${item.name}.txt` : item.name;
      a.click();
      setTimeout(() => {
        revokePlaintextUrl(url);
      }, 15_000);
      notify("Downloaded a decrypted copy. Keep it somewhere safe.");
    } catch (err) {
      if (current === generationRef.current) handleVaultError(err);
    }
  };
  const deletePermanently = async () => {
    if (!canUseVault()) return;
    if (!deleteItem) return;
    const current = generationRef.current;
    setBusy(true);
    try {
      if (!demo) await permanentlyDeleteVaultItem(deleteItem, vaultKey!);
      if (!workIsCurrent(current)) return;
      setItems((values) => values.filter((item) => item.id !== deleteItem.id));
      setDeleteItem(null);
      notify("File permanently deleted.");
    } catch (err) {
      if (current === generationRef.current) handleVaultError(err);
    } finally {
      if (current === generationRef.current) setBusy(false);
    }
  };

  const contentModal =
    modal === "setup" ? (
      <Modal
        concealed={policy.concealed}
        title={isFirebaseConfigured ? "Your vault is ready to connect" : "Make this space yours"}
        onClose={() => setModal(null)}
      >
        <div className="modal-feature-icon">
          <Fingerprint size={29} />
        </div>
        <h3 className="modal-title">Privacy starts with you.</h3>
        <p className="muted">
          You’re exploring sample files. Your personal vault uses a device passkey and a separate
          encryption passphrase.
        </p>
        <div className="setup-steps">
          <div>
            <span>1</span>
            <p>
              <strong>Connect Firebase</strong>
              <small>
                {isFirebaseConfigured
                  ? "Project configuration added. Security functions must be deployed."
                  : "Add your Firebase web app configuration."}
              </small>
            </p>
            {isFirebaseConfigured && <Check size={17} />}
          </div>
          <div>
            <span>2</span>
            <p>
              <strong>Register your passkey</strong>
              <small>Verify the owner account, then use your device.</small>
            </p>
          </div>
          <div>
            <span>3</span>
            <p>
              <strong>Create your passphrase</strong>
              <small>Only you can unlock your encrypted files.</small>
            </p>
          </div>
        </div>
        <button
          className="button primary full"
          onClick={() => {
            setModal(null);
            endSession();
          }}
        >
          Go to secure sign-in
          <ArrowRight size={17} />
        </button>
      </Modal>
    ) : modal === "help" ? (
      <Modal concealed={policy.concealed} title="A little peace of mind" onClose={() => setModal(null)}>
        <p className="muted">Haven is your private home for photos, documents, and notes.</p>
        <div className="help-item">
          <Fingerprint />
          <div>
            <h3>Two separate locks</h3>
            <p>
              Your device passkey verifies access. Your passphrase then decrypts your vault. A
              device may offer its PIN instead of biometrics.
            </p>
          </div>
        </div>
        <div className="help-item">
          <KeyRound />
          <div>
            <h3>Your passphrase stays yours</h3>
            <p>
              Files and filenames are encrypted in your browser. Save your passphrase in a safe
              place: it cannot be reset to recover your data.
            </p>
          </div>
        </div>
        <div className="help-item">
          <Image />
          <div>
            <h3>Look a little closer</h3>
            <p>
              Open a photo to zoom with the controls, mouse wheel, or a pinch. Drag to pan. Preview
              PDFs and text documents right here.
            </p>
          </div>
        </div>
        <div className="help-item">
          <LockKeyhole />
          <div>
            <h3>Private by default</h3>
            <p>
              Content is concealed immediately when you leave the tab. By default, the key is cleared after 30 seconds away or 5 minutes idle. Choose timings in Security. Locking keeps authentication active until its administrator-controlled expiry; Sign out ends it immediately on this device.
            </p>
          </div>
        </div>
      </Modal>
    ) : null;

  if (screen !== "vault")
    return (
      <div id="sensitive-surface" className="auth-layout" inert={policy.concealed || undefined}>
        {privacyScreen}
        {policy.warning && <SessionWarning />}
        <aside className="auth-story">
          <Brand light />
          <div className="auth-story-content">
            <div className="eyebrow">YOUR LIFE. YOUR EYES ONLY.</div>
            <h1>
              Some things
              <br />
              are just
              <br />
              <em>for you.</em>
            </h1>
            <p>
              The memories. The milestones. The important little details. Give them a place of their
              own.
            </p>
            <ArchIllustration />
          </div>
          <div className="auth-story-footer">
            <ShieldCheck size={17} /> Encrypted on your device. Private by design.
          </div>
        </aside>
        <main className="auth-main">
          <button className="auth-help text-button" onClick={() => openModal("help")}>
            <CircleHelp size={16} /> How Haven works
          </button>
          <div className="auth-card">
            {isEmulatorMode && <p className="setup-notice" role="status">Local testing · Firebase emulators · owner@example.com</p>}
            <div className="auth-progress">
              <span className={screen === "login" ? "current" : "complete"}>
                {screen === "login" ? "1" : <Check size={12} />}
                <b>Verify it’s you</b>
              </span>
              <i />
              <span className={screen !== "login" ? "current" : ""}>
                2<b>Unlock your vault</b>
              </span>
            </div>
            <div className="auth-icon">
              {screen === "login" ? <Fingerprint size={34} /> : <KeyRound size={32} />}
            </div>
            <div className="eyebrow">
              {screen === "login" ? "WELCOME TO YOUR PRIVATE SPACE" : "ONE MORE LAYER OF PRIVACY"}
            </div>
            <h1>
              {screen === "login"
                ? enrollmentStep ? "Create your passkey." : "A familiar touch."
                : screen === "create"
                  ? "Your key. Only yours."
                  : "Make yourself at home."}
            </h1>
            <p className="auth-description">
              {screen === "login"
                ? enrollmentStep
                  ? "Your Google account is verified. Continue here to create a passkey with your fingerprint, face, or device PIN."
                  : "Use your device passkey to enter. Your fingerprint, face, or device PIN opens the first door."
                : screen === "create"
                  ? "Choose a strong passphrase of at least 12 characters. A few unrelated words make a good start."
                  : "Your session is still active. Your passphrase unlocks your files locally; it is never sent to Firebase."}
            </p>
            {error && (
              <div className="error-message" role="alert">
                {error}
              </div>
            )}
            {screen === "login" && !isVaultBackendReady && (
              <div className="setup-notice"><Cloud size={17} /><span><strong>Preview ready. Secure storage setup pending.</strong>Firebase billing, Storage, and the security backend need activation before you can store personal files.</span></div>
            )}
            {screen === "login" ? (
              enrollmentStep ? (
                <>
                  <button
                    className="button primary full large"
                    disabled={enrollmentStep !== "confirm"}
                    onClick={() => enrollmentAction.current?.start()}
                  >
                    {enrollmentStep === "confirm" ? <Fingerprint size={21} /> : <LoaderCircle size={20} className="spin" />}
                    {enrollmentStep === "confirm" ? "Create my passkey" : "Waiting for your device…"}
                  </button>
                  <p className="auth-small" role="status">Keep this tab active while your device confirms it’s you.</p>
                  <button className="text-button full back-button" onClick={() => endSession()}>
                    <ArrowLeft size={15} /> Cancel setup
                  </button>
                </>
              ) : <>
                <button
                  className="button primary full large"
                  disabled={busy}
                  onClick={() => void authenticate(false)}
                >
                  {busy ? <LoaderCircle size={20} className="spin" /> : <Fingerprint size={21} />}
                  Sign in with passkey
                  <ArrowRight size={18} />
                </button>
                <div className="auth-divider">
                  <span>FIRST TIME HERE?</span>
                </div>
                <button
                  className="button secondary full"
                  disabled={busy}
                  onClick={() => void authenticate(true)}
                >
                  <Plus size={17} />
                  Set up my private vault
                </button>
                <p className="auth-small">
                  Setup is restricted to the vault owner’s Google account.
                </p>
                <button className="demo-link" onClick={enterDemo}>
                  Take a look around the demo
                  <ArrowRight size={15} />
                </button>
              </>
            ) : (
              <form onSubmit={decrypt}>
                <label className="field-label" htmlFor="passphrase">
                  {screen === "create" ? "Create a passphrase" : "Your passphrase"}
                </label>
                <div className="password-field">
                  <input
                    id="passphrase"
                    type={showPassphrase ? "text" : "password"}
                    autoFocus
                    autoComplete={screen === "create" ? "new-password" : "current-password"}
                    value={passphrase}
                    onChange={(event) => setPassphrase(event.target.value)}
                    minLength={12}
                    required
                    maxLength={1024}
                    placeholder="Something only you know"
                  />
                  <button
                    type="button"
                    className="icon-button"
                    aria-label={showPassphrase ? "Hide passphrase" : "Show passphrase"}
                    onClick={() => setShowPassphrase(!showPassphrase)}
                  >
                    {showPassphrase ? <EyeOff size={18} /> : <Eye size={18} />}
                  </button>
                </div>
                {screen === "create" && (
                  <>
                    <label className="field-label" htmlFor="confirm-passphrase">
                      Confirm passphrase
                    </label>
                    <input
                      id="confirm-passphrase"
                      className="text-input"
                      type="password"
                      autoComplete="new-password"
                      value={confirmPassphrase}
                      onChange={(event) => setConfirmPassphrase(event.target.value)}
                      minLength={12}
                      required
                      placeholder="One more time"
                    />
                    <label className="checkbox-label">
                      <input
                        type="checkbox"
                        required
                        checked={acknowledged}
                        onChange={(event) => setAcknowledged(event.target.checked)}
                      />
                      <span>
                        I’ve saved my passphrase securely. I understand that losing it means losing
                        access to my files.
                      </span>
                    </label>
                  </>
                )}
                <button className="button primary full large" disabled={busy} type="submit">
                  {busy ? <LoaderCircle className="spin" size={18} /> : <LockKeyhole size={18} />}
                  {busy
                    ? "Decrypting on your device…"
                    : screen === "create"
                      ? "Create my vault"
                      : "Unlock my vault"}
                </button>
                <button
                  type="button"
                  className="text-button full back-button"
                  onClick={() => endSession()}
                >
                  <ArrowLeft size={15} />
                  Sign out
                </button>
              </form>
            )}
            <Recovery key={`recovery-${generationRef.current}-${vaultState.status}`} authenticated={vaultState.status === 'locked'} onActive={setRecoveryActive}
              check={() => { if (recoveryGeneration !== generationRef.current || !canRevealContent()) throw new Error('Return to Haven to continue recovery.'); }}
              onFailure={handleVaultError} onComplete={() => endSession('Recovery complete. Sign in and unlock with your new passphrase.')} />
            {deadline > 0 && securitySettings}
            <div className="auth-reassurance">
              <LockKeyhole size={13} /> Your passphrase is never stored or shared.
            </div>
          </div>
          <footer className="auth-bottom">
            <span>A little space. A lot of peace of mind.</span>
            <span>HAVEN © {new Date().getFullYear()}</span>
          </footer>
        </main>
        {contentModal}
        {toast && (
          <div className="toast" role="status">
            <CheckCircle2 size={18} />
            {toast}
          </div>
        )}
      </div>
    );

  const statCards: { kind: Category; title: string; icon: ReactNode; className: string }[] = [
    { kind: "photo", title: "Photos", icon: <Image size={22} />, className: "photo-stat" },
    {
      kind: "document",
      title: "Documents",
      icon: <FileText size={22} />,
      className: "document-stat",
    },
    { kind: "note", title: "Secure notes", icon: <StickyNote size={22} />, className: "note-stat" },
  ];
  const collectionPicker = (
    <div className="form-field">
      <label className="field-label" htmlFor="item-collection">
        Collection
      </label>
      <select
        id="item-collection"
        className="text-input"
        value={uploadCollection}
        onChange={(event) => setUploadCollection(event.target.value)}
      >
        {allCollections.map((name) => (
          <option key={name}>{name}</option>
        ))}
      </select>
    </div>
  );

  return (
    <div id="sensitive-surface" className="app-shell" inert={policy.concealed || undefined}>
      {privacyScreen}
      {policy.warning && <SessionWarning />}
      {mobileNav && <div className="nav-overlay" onClick={() => setMobileNav(false)} />}
      <aside className={`sidebar ${mobileNav ? "nav-open" : ""}`}>
        <Brand />
        <div className="workspace-label">YOUR PRIVATE SPACE</div>
        <nav className="main-nav">
          {(
            [
              { name: "My vault", icon: <LayoutGrid /> },
              { name: "Recent", icon: <Clock3 /> },
              { name: "Favorites", icon: <Star /> },
            ] as { name: Section; icon: ReactNode }[]
          ).map((link) => (
            <button
              key={link.name}
              className={`nav-item ${section === link.name && !collection ? "active" : ""}`}
              onClick={() => openSection(link.name)}
            >
              {link.icon}
              <span>{link.name}</span>
              {link.name === "My vault" && <b>{liveItems.length}</b>}
            </button>
          ))}
        </nav>
        <div className="nav-section-label">
          COLLECTIONS
          <button
            className="icon-button"
            aria-label="New collection"
            onClick={() => openModal("collection")}
          >
            <Plus size={16} />
          </button>
        </div>
        <nav className="collection-nav">
          {allCollections.map((name, index) => (
            <button
              key={name}
              className={`nav-item ${collection === name ? "active" : ""}`}
              onClick={() => openSection("My vault", name)}
            >
              <FolderClosed className={`folder-color-${index % 3}`} size={18} />
              <span>{name}</span>
              <span className="collection-count">
                {liveItems.filter((item) => item.collection === name).length}
              </span>
            </button>
          ))}
        </nav>
        <div className="nav-separator" />
        <button
          className={`nav-item ${section === "Trash" ? "active" : ""}`}
          onClick={() => openSection("Trash")}
        >
          <Trash2 size={18} />
          <span>Trash</span>
        </button>
        <div className="sidebar-bottom">
          <button className="privacy-card" onClick={() => openSection("Security")}>
            <span className="privacy-icon">
              <ShieldCheck size={20} />
            </span>
            <strong>{demo ? "Private by design" : "Only you hold the key"}</strong>
            <p>
              Two layers of protection.
              <br />
              One less thing to worry about.
            </p>
            <span className="privacy-link">
              Your security <ArrowRight size={14} />
            </span>
          </button>
          <div className="storage-summary">
            <div>
              <span>
                <Cloud size={15} />
                {demo ? "Sample storage" : "Encrypted storage"}
              </span>
              <b>{formatBytes(totalSize)}</b>
            </div>
            <div className="storage-bar">
              <span />
            </div>
            <p>
              {liveItems.length}{" "}
              {demo ? "sample files to explore" : "files, encrypted before upload"}
            </p>
          </div>
          <button className="profile" onClick={() => openSection("Security")}>
            <span className="avatar">{demo ? "Y" : "JS"}</span>
            <span>
              <strong>{demo ? "Your personal vault" : "My personal vault"}</strong>
              <small>{demo ? "DEMO WORKSPACE" : "PRIVATE WORKSPACE"}</small>
            </span>
            <Settings2 size={17} />
          </button>
        </div>
      </aside>
      <div className="main-wrap">
        <header className="topbar">
          <div className="breadcrumb">
            <button
              className="icon-button mobile-menu"
              onClick={() => setMobileNav(true)}
              aria-label="Open navigation"
            >
              <Menu size={20} />
            </button>
            <span>Workspace</span>
            <span className="breadcrumb-slash">/</span>
            <strong>{collection || section}</strong>
          </div>
          <div className="topbar-actions">
            <span className={`session-status ${demo ? "demo-status" : ""}`}>
              <span />
              {demo ? "Demo workspace" : "Vault unlocked"}
            </span>
            <span className="topbar-divider" />
            <button
              className="lock-button"
              onClick={() => {
                lock(
                  demo
                    ? "Demo locked. Your real vault requires a passkey."
                    : "Your vault is locked.",
                );
              }}
            >
              <LockKeyhole size={15} />
              Lock vault
            </button>
            {!demo && <button className="lock-button" onClick={() => endSession()}>Sign out</button>}
            <button
              className="icon-button help-button"
              onClick={() => openModal("help")}
              aria-label="Help"
            >
              <CircleHelp size={19} />
            </button>
          </div>
        </header>
        <main className="main-content">
          {!demo && vaultState.status === 'unlocked' && vaultState.config.version === 2 && !vaultState.config.recovery && <div className="setup-notice" role="status"><span><strong>Recovery setup incomplete.</strong> Save and confirm a recovery kit in Security. Without a usable passphrase or recovery kit, content recovery is impossible.</span><button className="button secondary" onClick={() => openSection('Security')}>Set up recovery</button></div>}
          {section === "Security" ? (
            <>
              <div className="page-heading">
                <div>
                  <div className="eyebrow">PEACE OF MIND, BUILT IN</div>
                  <h1>Your privacy comes first.</h1>
                  <p>Two separate layers. A space that belongs to you.</p>
                </div>
                <ShieldCheck size={50} />
              </div>
              <section className="security-grid">
                <SecurityCard
                  icon={<Fingerprint />}
                  step="01"
                  title="Your device opens the door"
                  text="A verified passkey is required to access Firebase. Use your fingerprint, face, or the verification method offered by your device."
                  status={demo ? "Preview · not verified" : "Passkey verified"}
                />
                <SecurityCard
                  icon={<KeyRound />}
                  step="02"
                  title="Your passphrase holds the key"
                  text="AES-256-GCM encryption protects your files, filenames, and notes. Your passphrase or configured recovery kit unlocks the local master key."
                  status={demo ? "Preview · sample data" : "Vault decrypted in memory"}
                />
              </section>
              {securitySettings}
              {!demo && vaultState.status === 'unlocked' && <SecurityCenter config={vaultState.config} vaultKey={vaultState.key}
                check={() => { if (!canUseVault()) throw new Error('Unlock the vault to continue.'); }}
                onFailure={handleVaultError} onEndSession={() => endSession('This session was revoked.')}
                onChanged={(config, key) => { const state = stateRef.current; if (state.status === 'unlocked') transition({ ...state, config, key }); }} />}

              <div className="security-details">
                <h2>The little details that keep you safe</h2>
                {[
                  {
                    icon: <Clock3 />,
                    title: "Automatic locking",
                    description:
                      "Content is concealed immediately. Your chosen background and inactivity deadlines clear the key. The separate server session expiry signs you out.",
                  },
                  {
                    icon: <Cloud />,
                    title: "Encrypted before upload",
                    description:
                      "Firebase receives encrypted content and filenames. It does not receive your passphrase.",
                  },
                  {
                    icon: <HardDrive />,
                    title: "No decrypted offline cache",
                    description:
                      "Decryption keys and previews are kept in memory and released when the vault locks.",
                  },
                  {
                    icon: <KeyRound />,
                    title: "Recovery must be configured",
                    description:
                      "Configure and protect a recovery kit. Without a usable passphrase or kit, content recovery is impossible.",
                  },
                ].map((detail) => (
                  <div className="security-detail" key={detail.title}>
                    {detail.icon}
                    <div>
                      <h3>{detail.title}</h3>
                      <p>{detail.description}</p>
                    </div>
                    <Check size={18} />
                  </div>
                ))}
              </div>
              <div className="security-bottom">
                <p>
                  Browser passkeys may allow a device PIN. Protect your device and use a long,
                  unique vault passphrase.
                </p>
                <button className="button primary" onClick={() => lock()}>
                  <LockKeyhole size={16} />
                  Lock my vault
                </button>
              </div>
            </>
          ) : (
            <>
              <section className="welcome-banner">
                <div className="welcome-copy">
                  <span className="eyebrow">
                    <span className="tiny-line" /> A HOME FOR WHAT MATTERS
                  </span>
                  <h1>
                    A little space.
                    <br />
                    <span>A lot of peace of mind.</span>
                  </h1>
                  <p>
                    Your memories, documents, and important things.
                    <br className="desktop-break" /> All together. All just for you.
                  </p>
                  <div className="welcome-assurance">
                    <ShieldCheck size={15} />
                    <span>
                      {demo
                        ? "Discover a more private kind of cloud"
                        : "Encrypted on your device. Protected by your passphrase."}
                    </span>
                  </div>
                </div>
                <ArchIllustration />
                <span className="banner-corner">PERSONAL. PRIVATE. PROTECTED.</span>
              </section>
              <section className="stat-grid" aria-label="File categories">
                {statCards.map((stat) => {
                  const files = liveItems.filter((item) => item.kind === stat.kind);
                  return (
                    <button
                      key={stat.kind}
                      className={`stat-card ${stat.className} ${category === stat.kind ? "stat-selected" : ""}`}
                      onClick={() => {
                        setCategory(stat.kind);
                        setCollection("");
                        setSection("My vault");
                      }}
                    >
                      <span className="stat-icon">{stat.icon}</span>
                      <span className="stat-content">
                        <strong>{stat.title}</strong>
                        <span>
                          {files.length} {stat.kind === "note" ? "notes" : "files"}
                          <i>·</i>
                          {formatBytes(files.reduce((sum, item) => sum + item.size, 0))}
                        </span>
                      </span>
                      <ArrowRight size={18} className="stat-arrow" />
                    </button>
                  );
                })}
              </section>
              <section className="files-section">
                <div className="files-heading">
                  <div>
                    <h2>
                      {collection || (section === "My vault" ? "Your vault" : section)}
                      <span>{visibleItems.length}</span>
                    </h2>
                    <p>
                      {section === "Trash"
                        ? "A second chance for things you might still need."
                        : section === "Favorites"
                          ? "The things you want to keep close."
                          : section === "Recent"
                            ? "Your latest additions, all in one place."
                            : "Everything important, in its own safe place."}
                    </p>
                  </div>
                  <div className="file-actions">
                    <button
                      className="button secondary note-action"
                      onClick={() => openModal("note")}
                    >
                      <Plus size={16} />
                      New note
                    </button>
                    <button className="button primary" onClick={() => openModal("upload")}>
                      <Upload size={17} />
                      Upload files
                    </button>
                  </div>
                </div>
                <div className="file-toolbar">
                  <div className="category-tabs">
                    {(
                      [
                        { key: "all", label: "All files", icon: <LayoutGrid size={15} /> },
                        { key: "photo", label: "Photos", icon: <Image size={15} /> },
                        { key: "document", label: "Documents", icon: <FileText size={15} /> },
                        { key: "note", label: "Notes", icon: <StickyNote size={15} /> },
                      ] as { key: Category; label: string; icon: ReactNode }[]
                    ).map((tab) => (
                      <button
                        key={tab.key}
                        className={category === tab.key ? "selected" : ""}
                        onClick={() => setCategory(tab.key)}
                      >
                        {tab.icon}
                        {tab.label}
                      </button>
                    ))}
                  </div>
                  <label className="search-box">
                    <Search size={16} />
                    <input
                      ref={searchRef}
                      value={search}
                      onChange={(event) => setSearch(event.target.value)}
                      placeholder="Find something…"
                      aria-label="Search vault"
                    />
                    {search ? (
                      <button
                        className="icon-button"
                        onClick={() => setSearch("")}
                        aria-label="Clear search"
                      >
                        <X size={13} />
                      </button>
                    ) : (
                      <kbd>⌘ K</kbd>
                    )}
                  </label>
                </div>
                <div className="file-subtoolbar">
                  <span>
                    {search
                      ? `Results for “${search}”`
                      : section === "Trash"
                        ? "DELETED FILES"
                        : "YOUR PRIVATE COLLECTION"}
                  </span>
                  <div>
                    <label className="sort-control">
                      <ArrowDown size={13} />
                      <select
                        aria-label="Sort files"
                        value={sort}
                        onChange={(event) => setSort(event.target.value)}
                      >
                        <option value="newest">Newest first</option>
                        <option value="name">Name A–Z</option>
                        <option value="size">Largest first</option>
                      </select>
                      <ChevronDown size={12} />
                    </label>
                    <div className="view-toggle">
                      <button
                        className={view === "grid" ? "selected" : ""}
                        onClick={() => setView("grid")}
                        aria-label="Grid view"
                      >
                        <Grid2X2 size={16} />
                      </button>
                      <button
                        className={view === "list" ? "selected" : ""}
                        onClick={() => setView("list")}
                        aria-label="List view"
                      >
                        <List size={17} />
                      </button>
                    </div>
                  </div>
                </div>
                {visibleItems.length === 0 ? (
                  <div className="empty-state">
                    <span>
                      <Folder size={32} />
                    </span>
                    <h3>
                      {search
                        ? "Nothing here by that name."
                        : section === "Favorites"
                          ? "Keep your favorites close."
                          : section === "Trash"
                            ? "A clean slate."
                            : "Good things belong here."}
                    </h3>
                    <p>
                      {search
                        ? "Try another word or clear your search."
                        : section === "Favorites"
                          ? "Star any file to find it here."
                          : section === "Trash"
                            ? "Deleted files will appear here until you remove them permanently."
                            : "Add a photo, a document, or a little note to yourself."}
                    </p>
                    <button
                      className="button secondary"
                      onClick={() => (search ? setSearch("") : openModal("upload"))}
                    >
                      {search ? "Clear search" : "Add your first file"}
                      <Plus size={15} />
                    </button>
                  </div>
                ) : (
                  <div className={`file-grid ${view === "list" ? "file-list" : ""}`}>
                    {visibleItems.map((item) => (
                      <article className={`file-card ${item.kind}-card`} key={item.id}>
                        <button
                          className="file-thumbnail"
                          onClick={() => setPreviewId(item.id)}
                          aria-label={`Preview ${item.name}`}
                        >
                          <FileCover item={item} vaultKey={vaultKey} />
                          <span className="preview-hover">
                            <Eye size={18} />
                            Quick look
                          </span>
                          <span className="file-type-badge">
                            {item.kind === "photo"
                              ? item.name.split(".").pop()?.toUpperCase()
                              : item.kind === "note"
                                ? "NOTE"
                                : item.name.split(".").pop()?.toUpperCase()}
                          </span>
                        </button>
                        <button
                          className={`favorite-button ${item.favorite ? "is-favorite" : ""}`}
                          aria-label={
                            item.favorite ? `Unfavorite ${item.name}` : `Favorite ${item.name}`
                          }
                          onClick={() => void changeItem(item, { favorite: !item.favorite })}
                        >
                          <Star size={15} fill={item.favorite ? "currentColor" : "none"} />
                        </button>
                        <div className="file-info">
                          <button
                            className="file-name"
                            title={item.name}
                            onClick={() => setPreviewId(item.id)}
                          >
                            {item.name}
                          </button>
                          <div className="file-meta">
                            <span>{formatBytes(item.size)}</span>
                            <i>·</i>
                            <span>{prettyDate(item.createdAt)}</span>
                          </div>
                          <div className="file-bottom">
                            <span
                              className={`collection-pill collection-${item.collection.toLowerCase()}`}
                            >
                              <span />
                              {item.collection}
                            </span>
                            <div className="item-menu-wrap">
                              <button
                                className="icon-button more-button"
                                aria-label={`Actions for ${item.name}`}
                                onClick={(event) => {
                                  event.stopPropagation();
                                  setMenuId(menuId === item.id ? null : item.id);
                                }}
                              >
                                <MoreHorizontal size={18} />
                              </button>
                              {menuId === item.id && (
                                <ItemMenu>
                                  <button
                                    onClick={() => {
                                      setPreviewId(item.id);
                                      setMenuId(null);
                                    }}
                                  >
                                    <Eye size={15} />
                                    Preview
                                  </button>
                                  <button
                                    onClick={() => {
                                      void download(item);
                                      setMenuId(null);
                                    }}
                                  >
                                    <ArrowDownToLine size={15} />
                                    Download
                                  </button>
                                  <button
                                    onClick={() =>
                                      void changeItem(item, { favorite: !item.favorite })
                                    }
                                  >
                                    <Star size={15} />
                                    {item.favorite ? "Remove favorite" : "Add to favorites"}
                                  </button>
                                  {item.trashed ? (
                                    <>
                                      <button
                                        onClick={() => void changeItem(item, { trashed: false })}
                                      >
                                        <RotateCcw size={15} />
                                        Restore file
                                      </button>
                                      <button
                                        className="danger"
                                        onClick={() => {
                                          setDeleteItem(item);
                                          setMenuId(null);
                                        }}
                                      >
                                        <Trash2 size={15} />
                                        Delete permanently
                                      </button>
                                    </>
                                  ) : (
                                    <button
                                      className="danger"
                                      onClick={() => void changeItem(item, { trashed: true })}
                                    >
                                      <Trash2 size={15} />
                                      Move to trash
                                    </button>
                                  )}
                                </ItemMenu>
                              )}
                            </div>
                          </div>
                        </div>
                      </article>
                    ))}
                  </div>
                )}
              </section>
              {demo && (
                <div className="demo-banner">
                  <span>
                    <Sparkles size={16} />
                    <strong>A little look inside Haven.</strong> These are sample files. Make this
                    space your own.
                  </span>
                  <button onClick={() => openModal("setup")}>
                    Set up your vault
                    <ArrowRight size={15} />
                  </button>
                </div>
              )}
              <footer className="vault-footer">
                <span>
                  <LockKeyhole size={13} />
                  {demo
                    ? "Your real files deserve a private home."
                    : "Encrypted on your device. Readable only with your passphrase."}
                </span>
                <span>
                  Made for your peace of mind <span className="footer-flower">✳</span>
                </span>
              </footer>
            </>
          )}
        </main>
      </div>
      {preview && (
        <Preview
          key={preview.id}
          item={preview}
          vaultKey={vaultKey}
          onClose={() => setPreviewId(null)}
          onAuthenticationFailure={handleVaultError}
          canReveal={canRevealContent}
          onDownload={(item) => void download(item)}
          onStep={(offset) => {
            const index = visibleItems.findIndex((item) => item.id === preview.id);
            if (visibleItems.length)
              setPreviewId(
                visibleItems[(index + offset + visibleItems.length) % visibleItems.length].id,
              );
          }}
        />
      )}
      {modal === "upload" && (
        <Modal
        concealed={policy.concealed}
          title="A safe place for your files"
          onClose={() => {
            if (!busy) setModal(null);
          }}
        >
          <p className="muted">
            Photos, documents, and the things you want to keep. Up to 50 MB per file.
          </p>
          <button
            className={`upload-dropzone ${dragging ? "dragging" : ""}`}
            disabled={busy}
            onClick={() => uploadRef.current?.click()}
            onDragOver={(event) => {
              event.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={(event) => {
              event.preventDefault();
              setDragging(false);
              void upload(event.dataTransfer.files);
            }}
          >
            <span>
              <Upload size={28} />
            </span>
            <strong>{busy ? progress : "Drop something important here"}</strong>
            <small>
              {busy
                ? "Your files are encrypted before they leave this device."
                : "or click to browse your files"}
            </small>
            <div className="upload-file-types">JPG · PNG · PDF · DOCX · AND MORE</div>
          </button>
          <input
            ref={uploadRef}
            type="file"
            multiple
            hidden
            onChange={(event) => {
              if (event.target.files) void upload(event.target.files);
              event.target.value = "";
            }}
          />
          {collectionPicker}
          {error && (
            <div className="error-message" role="alert">
              {error}
            </div>
          )}
          <div className="upload-note">
            <LockKeyhole size={15} />
            {demo
              ? "Sample workspace. Set up your vault to store real files."
              : "Your files and filenames are encrypted with your key."}
          </div>
        </Modal>
      )}
      {modal === "note" && (
        <Modal
        concealed={policy.concealed}
          title="A little note to yourself"
          onClose={() => {
            if (!busy) setModal(null);
          }}
        >
          <form onSubmit={saveNote}>
            <label className="field-label" htmlFor="note-title">
              Title
            </label>
            <input
              className="text-input"
              id="note-title"
              required
              maxLength={200}
              autoFocus
              value={noteTitle}
              onChange={(event) => setNoteTitle(event.target.value)}
              placeholder="Give your thought a name"
            />
            <label className="field-label" htmlFor="note-content">
              Your note
            </label>
            <textarea
              className="text-input note-textarea"
              id="note-content"
              required
              maxLength={200000}
              value={noteText}
              onChange={(event) => setNoteText(event.target.value)}
              placeholder="Some things are just for you…"
            />
            {collectionPicker}
            {error && (
              <div className="error-message" role="alert">
                {error}
              </div>
            )}
            <button className="button primary full" type="submit" disabled={busy}>
              {busy ? <LoaderCircle className="spin" size={17} /> : <LockKeyhole size={17} />}Save
              encrypted note
            </button>
          </form>
        </Modal>
      )}
      {modal === "collection" && (
        <Modal concealed={policy.concealed} title="A place for everything" onClose={() => setModal(null)}>
          <p className="muted">
            Give related files a little home of their own. Collections are saved with the files you
            add to them.
          </p>
          <form
            onSubmit={(event) => {
              event.preventDefault();
              const name = newCollection.trim();
              if (
                !name ||
                allCollections.some((value) => value.toLowerCase() === name.toLowerCase())
              ) {
                setError("Choose a new, unique collection name.");
                return;
              }
              setCollections((values) => [...values, name]);
              setNewCollection("");
              setModal(null);
              openSection("My vault", name);
              setUploadCollection(name);
              notify("Collection created. Add a file to keep it in your vault.");
            }}
          >
            <label className="field-label" htmlFor="collection-name">
              Collection name
            </label>
            <input
              id="collection-name"
              autoFocus
              required
              maxLength={60}
              className="text-input"
              value={newCollection}
              onChange={(event) => setNewCollection(event.target.value)}
              placeholder="A name that feels right"
            />
            {error && <div className="error-message">{error}</div>}
            <button className="button primary full" type="submit">
              <Plus size={17} />
              Create collection
            </button>
          </form>
        </Modal>
      )}
      {contentModal}
      {deleteItem && (
        <Modal
        concealed={policy.concealed}
          title="Delete this file permanently?"
          onClose={() => {
            if (!busy) setDeleteItem(null);
          }}
        >
          <p className="muted">
            <strong>{deleteItem.name}</strong> will be removed from your vault. This cannot be
            undone.
          </p>
          <div className="modal-buttons">
            <button className="button secondary" onClick={() => setDeleteItem(null)}>
              Keep file
            </button>
            <button
              className="button danger-button"
              disabled={busy}
              onClick={() => void deletePermanently()}
            >
              <Trash2 size={16} />
              Delete permanently
            </button>
          </div>
        </Modal>
      )}
      {toast && (
        <div className="toast" role="status">
          <CheckCircle2 size={18} />
          {toast}
          <button
            className="icon-button"
            onClick={() => setToast("")}
            aria-label="Dismiss notification"
          >
            <X size={14} />
          </button>
        </div>
      )}
    </div>
  );
}

function SessionWarning() {
  return <div className="session-warning" role="alert">Your authentication session ends in less than a minute. Completed uploads remain saved. Unfinished uploads and unsaved edits may be lost. Sign in again with your passkey after expiry, then unlock with your passphrase.</div>;
}

function SecurityCard({
  icon,
  step,
  title,
  text,
  status,
}: {
  icon: ReactNode;
  step: string;
  title: string;
  text: string;
  status: string;
}) {
  return (
    <article className="security-card">
      <div className="security-card-top">
        <span>{icon}</span>
        <b>LAYER {step}</b>
      </div>
      <h2>{title}</h2>
      <p>{text}</p>
      <span className="security-card-status">
        <Circle size={7} fill="currentColor" />
        {status}
      </span>
    </article>
  );
}

function FileCover({ item }: { item: DisplayItem; vaultKey: CryptoKey | null }) {
  // Thumbnails are inside the encrypted metadata. The grid never downloads and
  // decrypts every full-resolution original just to show a small image.
  const thumbnail = item.demoUrl || item.thumbnail || "";
  if (item.kind === "photo")
    return thumbnail ? (
      <img src={thumbnail} alt="" loading="lazy" />
    ) : (
      <div className="photo-placeholder">
        <Image size={35} />
        <span>Encrypted photo</span>
      </div>
    );
  if (item.kind === "note")
    return (
      <div className="note-cover">
        <div className="note-cover-top">
          <StickyNote size={14} />
          <span>JUST FOR YOU</span>
        </div>
        <h3>{item.name}</h3>
        <p>
          {item.text?.split("\n").filter(Boolean).slice(1).join("\n").slice(0, 175) ||
            "A little space for your thoughts."}
        </p>
        <span className="note-cover-dash" />
      </div>
    );
  return (
    <div className={`document-cover ${item.id === "demo-passport" ? "travel-cover" : ""}`}>
      <div className="paper-sheet">
        <div className="paper-topline" />
        <div className="paper-mini-brand">
          {item.id === "demo-passport" ? "THE NEXT ADVENTURE" : "PERSONAL ARCHIVE"}
        </div>
        <div className="paper-title">{item.name.replace(/\.[^.]+$/, "")}</div>
        <div className="paper-subtitle">The important little details.</div>
        <div className="paper-rule" />
        <div className="paper-lines">
          <i />
          <i />
          <i />
          <i />
        </div>
        <div className="paper-seal">
          {item.id === "demo-passport" ? (
            <svg viewBox="0 0 70 60">
              <path
                d="M5 50 25 17 42 50M26 50 45 8 66 50M17 31l8 8 7-9M36 26l9 8 8-9"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.5"
              />
            </svg>
          ) : (
            <ShieldCheck size={27} />
          )}
        </div>
      </div>
    </div>
  );
}
