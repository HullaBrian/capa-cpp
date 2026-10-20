#include "view_results.h"

#include <algorithm>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include <dirtree.hpp>

#include "ida/helpers.h"
#include "plugin.h"
#include "settings.h"

namespace idacapa {

const char* const RESULTS_TITLE = "capa explorer";

namespace {

const int WIDTHS[] = {56, 12 | CHCOL_EA, 44};
const char* const HEADERS[] = {"Rule Information", "Address", "Functions"};

std::string ea_to_hex(ea_t ea) {
    char buf[32];
    qsnprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(ea));
    return buf;
}

// A folder path component cannot contain a separator, and "." / ".." are navigation
// rather than names.
std::string sanitize(const std::string& name) {
    std::string out;
    out.reserve(name.size());
    for (char c : name)
        out.push_back(c == '/' || c == '\\' || c == DIRTREE_FOLDED_SEP ? '_' : c);
    if (out.empty() || out == "." || out == "..") out.insert(out.begin(), '_');
    return out;
}

bool is_scope_kind(NodeKind k) {
    return k == NodeKind::Function || k == NodeKind::BasicBlock || k == NodeKind::Instruction;
}

// The IDB's name for the function a match is in, for the Functions column. Every
// scope resolves to one: a function-scope match is the function, and an instruction-
// or basic-block-scope match sits inside one. Empty when the address belongs to no
// function at all -- a file-scope match, which has no address, or a match in data.
std::string function_name_at(ea_t ea) {
    if (ea == BADADDR || !is_mapped(ea)) return {};
    ea_t fea = capa::ida::func_start_of(ea);
    if (fea == BADADDR) return {};
    return capa::ida::get_function_name_at(fea);
}

// One row: a single match of a single rule.
struct Row {
    std::string label;   // unique within its folder
    std::string rule;    // the rule's name, without any disambiguating suffix
    std::string ns;      // the rule's namespace
    std::string details;
    ea_t address = BADADDR;
    const ResultNode* rule_node = nullptr;   // for "annotate selected rule"
    const ResultNode* match_node = nullptr;  // for the details pane
    inode_t inode = inode_t(0);
};

// Teaches dirtree_t what our inodes are. An inode is the row index + 1 (0 is the
// dirtree's own root), unique and stable for one build of the tree.
struct InodeSource {
    virtual ~InodeSource() = default;
    virtual bool name_of_inode(qstring* out, inode_t inode) const = 0;
    virtual inode_t inode_in_dir(const char* dirpath, const char* name) const = 0;
};

struct RowSpec : public dirspec_t {
    // No netnode id: the tree is rebuilt from the results every time the window opens,
    // so there is nothing worth saving, and a saved copy could only go stale.
    //
    // DSF_UNQ_NAMES because our labels really are globally unique -- a label is a capa
    // rule name, and capa requires those to be unique across the rule set (a rule that
    // matched more than once carries the match address as well). Telling IDA that lets
    // it identify an entry by name instead of by reconstructing its path, which is the
    // step that breaks when it folds a chain of single-child folders together.
    explicit RowSpec(InodeSource& source)
        : dirspec_t(nullptr, DSF_UNQ_NAMES), source(source) {}

    bool get_name(qstring* out, inode_t inode, uint32 /*flags*/) override {
        qstring name;
        if (!source.name_of_inode(&name, inode)) return false;
        if (out != nullptr) *out = name;
        return true;
    }
    inode_t get_inode(const char* dirpath, const char* name) override {
        return source.inode_in_dir(dirpath, name);
    }
    qstring get_attrs(inode_t /*inode*/) const override { return qstring(); }
    // Renaming a capa result would mean renaming a rule; rules are files on disk.
    bool rename_inode(inode_t /*inode*/, const char* /*newname*/) override { return false; }

    InodeSource& source;
};

}  // namespace

// ---------------------------------------------------------------------------

// CH_KEEP: this chooser is owned by ResultsView, not by IDA. It is a STANDALONE
// window: an embedded chooser does not render a dirtree (see ResultsView::open).
struct ResultsView::Chooser : public chooser_t, private InodeSource {
    Chooser(ResultsView& owner, const ResultsDoc& doc)
        // The title is both the window's caption and how find_widget() and
        // refresh_chooser() locate it.
        : chooser_t(CH_KEEP | CH_CAN_REFRESH | HAS_DIRTREE | FULL_TREE, qnumber(WIDTHS),
                    WIDTHS, HEADERS, RESULTS_TITLE),
          m_owner(owner),
          m_doc(doc),
          m_tree(new dirtree_t(new RowSpec(*this))) {
        build(/*announce=*/true);
    }

    ~Chooser() override {
        // Before the InodeSource base goes away: the dirtree owns its dirspec, and the
        // dirspec points back at us.
        m_tree.reset();
    }

    // --- chooser_t ---------------------------------------------------------

    size_t idaapi get_count() const override { return m_rows.size(); }

    void idaapi get_row(qstrvec_t* out, int* /*icon*/, chooser_item_attrs_t* /*attrs*/,
                        size_t n) const override {
        if (out->size() < qnumber(WIDTHS)) out->resize(qnumber(WIDTHS));

        // Returning without touching `out` leaves whatever the caller had there, which
        // renders as an empty row and looks like a result with no text rather than a
        // bug. If the dirtree ever asks for a row we do not have, say so.
        if (n >= m_rows.size()) {
            (*out)[0] = "(stale row - re-run the analysis)";
            (*out)[1] = "";
            (*out)[2] = "";
            return;
        }

        const Row& row = m_rows[n];
        (*out)[0] = row.label.c_str();
        (*out)[1] = row.address == BADADDR ? "" : ea_to_hex(row.address).c_str();
        (*out)[2] = row.details.c_str();
    }

    ea_t idaapi get_ea(size_t n) const override {
        return n < m_rows.size() ? m_rows[n].address : BADADDR;
    }

    // Double-click / Enter on a match: go there. Expanding and collapsing is the
    // dirtree's own gesture, so this never has to guess between the two.
    cbret_t idaapi enter(size_t n) override {
        if (n < m_rows.size()) {
            show_details(n, /*activate=*/false);
            const ea_t ea = m_rows[n].address;
            if (ea != BADADDR && is_mapped(ea)) jumpto(ea);
        }
        return cbret_t(ssize_t(n), NOTHING_CHANGED);
    }

    // The cursor moved: follow it in the details pane, without stealing focus.
    void idaapi select(ssize_t n) const override {
        m_current = n;
        if (n >= 0) show_details(static_cast<size_t>(n), /*activate=*/false);
    }

    cbret_t idaapi refresh(ssize_t /*n*/) override {
        refilter();
        return cbret_t(NO_SELECTION, ALL_CHANGED);
    }

    dirtree_t* idaapi get_dirtree() override { return m_tree.get(); }

    inode_t idaapi index_to_inode(size_t n) const override {
        return n < m_rows.size() ? m_rows[n].inode : inode_t(BADADDR);
    }

    size_t idaapi inode_to_index(inode_t inode) const override {
        const auto it = m_by_inode.find(inode);
        return it == m_by_inode.end() || it->second >= m_rows.size() ? size_t(-1) : it->second;
    }

    const void* get_obj_id(size_t* len) const override {
        *len = sizeof(m_id);
        return &m_id;
    }

    // --- contents ----------------------------------------------------------

    // Show different results in the window that is already up.
    void set_content(const ResultsDoc& doc) {
        clear_tree();
        m_doc = doc;
        build(/*announce=*/true);
    }

    // Re-evaluate the row filter against the results already on display.
    void refilter() {
        clear_tree();
        build();
    }

    const ResultsDoc& doc() const { return m_doc; }

    const ResultNode* selected_rule() const {
        if (m_current < 0 || static_cast<std::size_t>(m_current) >= m_rows.size()) return nullptr;
        return m_rows[m_current].rule_node;
    }

private:
    // --- InodeSource -------------------------------------------------------

    bool name_of_inode(qstring* out, inode_t inode) const override {
        const auto it = m_by_inode.find(inode);
        if (it == m_by_inode.end() || it->second >= m_rows.size()) return false;
        if (out != nullptr) *out = m_rows[it->second].label.c_str();
        return true;
    }

    inode_t inode_in_dir(const char* dirpath, const char* name) const override {
        std::string key = dirpath == nullptr ? std::string() : dirpath;

        // IDA FOLDS a chain of single-child directories into one entry, and spells the
        // folded path with DIRTREE_FOLDED_SEP where the separators were -- so it asks
        // for "/anti-analysis\x1danti-debugging\x1ddebugger-detection/" while we keyed
        // the row under "/anti-analysis/anti-debugging/debugger-detection/". The lookup
        // missed, IDA could not resolve the entry, and the row rendered with no content
        // at all. Deeply nested namespaces fold; ones with siblings at every level do
        // not, which is why only some of them were blank.
        std::replace(key.begin(), key.end(), DIRTREE_FOLDED_SEP, '/');

        if (!key.empty() && key.back() != '/') key.push_back('/');
        key += name == nullptr ? "" : name;
        if (const auto it = m_by_path.find(key); it != m_by_path.end()) return it->second;

        // Fall back to the label alone. Rule names are unique across the rule set, so a
        // label identifies a row on its own; this catches any other reshaping of the
        // path we have not anticipated rather than silently yielding a blank row.
        if (name != nullptr) {
            if (const auto it = m_by_label.find(name); it != m_by_label.end())
                return it->second;
        }
        return inode_t(BADADDR);
    }

    // --- building ----------------------------------------------------------

    void show_details(size_t n, bool activate) const {
        if (n >= m_rows.size()) return;
        const Row& row = m_rows[n];
        if (row.match_node == nullptr) return;
        m_owner.plugin().details().show(row.rule, row.ns, *row.match_node, activate);
    }

    bool keep(ea_t address) const {
        if (!m_limit_valid) return true;
        return address != BADADDR && capa::ida::func_start_of(address) == m_limit_func_ea;
    }

    // Make the folder path for a namespace, creating each component.
    // Returns "/" for a rule with no namespace, or "" if the tree refused a component.
    std::string make_folders(const std::string& ns) {
        if (ns.empty()) return "/";
        std::string path;
        std::size_t pos = 0;
        while (pos <= ns.size()) {
            std::size_t sep = ns.find('/', pos);
            std::string part =
                ns.substr(pos, sep == std::string::npos ? std::string::npos : sep - pos);
            if (!part.empty()) {
                path += "/" + sanitize(part);
                const dterr_t err = m_tree->mkdir(path.c_str());
                if (err != DTE_OK && err != DTE_ALREADY_EXISTS) return {};
                // Recorded whether or not we created it. Nothing else uses this
                // dirtree, so a folder that "already exists" is one an earlier build
                // of ours left behind -- and leaving it out of the list is how it
                // would leak forever.
                m_folders.push_back(path);
            }
            if (sep == std::string::npos) break;
            pos = sep + 1;
        }
        return path.empty() ? "/" : path;
    }

    // Empty the tree without replacing it. The dirtree object itself must outlive the
    // widget — IDA holds the pointer get_dirtree() gave it — so its *contents* are what
    // change when the results do.
    void clear_tree() {
        // By ABSOLUTE PATH, not by inode. dirtree_t::unlink(inode_t) removes the inode
        // from the CURRENT directory only -- so unlinking by inode from wherever the
        // cwd happens to be silently failed for every row that lives in a namespace
        // folder, which is all of them. Those inodes stayed linked; rmdir then failed
        // with DTE_NOT_EMPTY, so the folders survived too; and on the next build
        // link() hit DTE_ALREADY_EXISTS against the stale entry and the new row never
        // made it into its folder. That is one bug wearing two faces: rows that render
        // with no name, and rows that all pile up in the same place instead of under
        // their namespace.
        for (const auto& [path, inode] : m_by_path) m_tree->unlink(path.c_str());

        // Deepest first: a folder cannot be removed while it still has children.
        // Sorted by length rather than trusting insertion order -- a child's path is
        // always longer than its parent's, because it contains it as a prefix.
        std::sort(m_folders.begin(), m_folders.end(),
                  [](const std::string& a, const std::string& b) { return a.size() > b.size(); });
        for (const std::string& dir : m_folders) m_tree->rmdir(dir.c_str());

        m_folders.clear();
        m_rows.clear();
        m_by_inode.clear();
        m_by_path.clear();
        m_by_label.clear();
        m_current = NO_SELECTION;  // row indices no longer mean anything
    }

    // `announce` only for the builds a user initiated -- opening the window and loading
    // new results. refilter() runs on cursor movement and must stay silent.
    void build(bool announce = false) {
        m_link_failures = 0;
        m_flat = flat_results();
        m_limit_valid = false;
        if (limit_to_current_function()) {
            ea_t fea = capa::ida::func_start_of(get_screen_ea());
            if (fea != BADADDR) {
                m_limit_func_ea = fea;
                m_limit_valid = true;
            }
        }

        for (const ResultNode& rule : m_doc.rules) {
            // A rule's matches are its scope children; a file-scope rule has no scope
            // node, and matches exactly once, so the rule node is the match.
            std::vector<const ResultNode*> matches;
            for (const ResultNode& child : rule.children)
                if (is_scope_kind(child.kind)) matches.push_back(&child);
            if (matches.empty()) matches.push_back(&rule);

            const bool many = matches.size() > 1;
            // Flat mode puts every row in the root and carries the namespace in a
            // column, so nothing depends on IDA rendering a dirtree inside an embedded
            // chooser. Sorted by (namespace, name) upstream, so the list still reads in
            // namespace order.
            const std::string path =
                m_flat ? std::string("/") : make_folders(rule.details);
            if (path.empty()) continue;  // tree refused the folder
            if (m_tree->chdir(path.c_str()) != DTE_OK) continue;

            std::size_t row_of_rule = 0;
            for (const ResultNode* match : matches) {
                ++row_of_rule;
                if (!keep(match->address)) continue;

                Row row;
                row.rule = rule.info;
                row.ns = rule.details;
                row.address = match->address;
                // What a reader wants beside a match is where it is, and the name the
                // database gives that place. A disassembly preview said `push ebp` for
                // every function-scope rule in the list; the column holds the
                // containing function's name instead, whatever the rule's scope.
                // Left empty when there is no function -- a name is the only thing
                // this column claims to hold.
                row.details = function_name_at(match->address);
                row.rule_node = &rule;
                row.match_node = match;

                // Labels must be unique within a folder: that is how the dirtree
                // resolves a path back to a row. One match is just the rule's name;
                // repeats carry their address.
                row.label = sanitize(rule.info);
                // A row with no name is not a result, it is a symptom -- a cache
                // written by a build whose node shape differed parses as valid JSON
                // with every field missing. Drop it rather than render a blank row.
                if (row.label.empty()) continue;
                // In flat mode every row shares one directory, so the label has to be
                // unique across the whole result set rather than within a namespace.
                if (m_flat && !row.ns.empty()) row.label = sanitize(row.ns) + " / " + row.label;
                if (many) {
                    // An addressless match still needs a distinct label, or the second
                    // one collides on `key` below and is dropped from the tree.
                    row.label += match->address != BADADDR
                                     ? " @ " + ea_to_hex(match->address)
                                     : " (" + std::to_string(row_of_rule) + ")";
                }

                row.inode = static_cast<inode_t>(m_rows.size() + 1);
                const std::string key = (path == "/" ? "/" : path + "/") + row.label;
                if (m_by_path.count(key)) continue;  // would corrupt the tree

                m_by_path[key] = row.inode;
                m_by_label[row.label] = row.inode;
                m_by_inode[row.inode] = m_rows.size();
                const inode_t inode = row.inode;
                const std::string label = row.label;  // for the rollback below
                m_rows.push_back(std::move(row));

                // Only now: link() asks the dirspec for the inode's name, and that name
                // comes from the row.
                //
                // A failure has to undo the row as well. get_count() is m_rows.size(),
                // so a row the tree never accepted is a row the chooser will ask about
                // and the tree cannot place -- which is exactly what a phantom row is.
                // Keeping the two in lockstep makes that state unrepresentable.
                const dterr_t err = m_tree->link(inode);
                if (err != DTE_OK) {
                    m_rows.pop_back();
                    m_by_inode.erase(inode);
                    m_by_path.erase(key);
                    m_by_label.erase(label);
                    ++m_link_failures;
                }
            }
        }

        // A row the tree refused is a match the user cannot see, so it is not something
        // to swallow quietly.
        if (m_link_failures > 0)
            msg("capa: %d result row(s) could not be placed in the tree and are not "
                "shown; please report this.\n",
                static_cast<int>(m_link_failures));

        // make_folders() records a path per rule that touches it, so the same folder
        // appears once per rule in its namespace. Dedupe before anyone counts them or
        // tries to remove them.
        std::sort(m_folders.begin(), m_folders.end());
        m_folders.erase(std::unique(m_folders.begin(), m_folders.end()), m_folders.end());

        // Same reasoning: a row with no label is a match the user cannot read.
        if (announce) {
            std::size_t blank = 0;
            for (const Row& r : m_rows)
                if (r.label.empty()) ++blank;
            if (blank > 0)
                msg("capa: %d result row(s) have an empty label; please report this.\n",
                    static_cast<int>(blank));
        }

        m_tree->chdir("/");
    }

    ResultsView& m_owner;
    const ResultsView* m_id = &m_owner;
    // A copy, not a reference: the window outlives the analysis that produced it, and
    // the rows point into this doc.
    ResultsDoc m_doc;

    std::vector<Row> m_rows;
    std::unordered_map<inode_t, std::size_t> m_by_inode;
    std::map<std::string, inode_t> m_by_path;
    // label -> inode, for resolving an entry when the path IDA hands back has been
    // reshaped. Rule names are unique across the rule set, so a label identifies a row.
    std::map<std::string, inode_t> m_by_label;
    // The folders this build created, in creation order, so clear_tree() can take them
    // back out from the leaves up.
    std::vector<std::string> m_folders;
    std::size_t m_link_failures = 0;
    bool m_flat = false;
    // Created once and kept for the chooser's whole life; only its contents change.
    std::unique_ptr<dirtree_t> m_tree;
    mutable ssize_t m_current = NO_SELECTION;

    ea_t m_limit_func_ea = BADADDR;
    bool m_limit_valid = false;

    // The two flags that make a chooser tree-shaped, and they are two: one says a
    // dirtree exists, the other says to draw it. The drawing one is a 2-bit mode field
    // whose zero value renders the tree as a flat list of leaves — and IDA still
    // resolves clicks through the tree it is not drawing, so rows stop responding.
    // Both are deprecated in 9.4 with nothing to replace them; named here so there is
    // one place to change when they go.
    static constexpr uint32 HAS_DIRTREE = OBSOLETE_CH_HAS_DIRTREE;
    static constexpr uint32 FULL_TREE = OBSOLETE_CH_TM_FULL_TREE;
};

// ---------------------------------------------------------------------------

ResultsView* ResultsView::s_active = nullptr;

ResultsView::ResultsView(PluginCtx& plugin) : m_plugin(plugin) {}

ResultsView::~ResultsView() {
    close_window();
    // Nothing of IDA's can be pointing at either of these any more.
    m_retired.reset();
    m_chooser.reset();
}

void ResultsView::close_window() {
    if (s_active == this) s_active = nullptr;

    if (m_widget != nullptr) {
        TWidget* w = m_widget;
        m_widget = nullptr;  // before close_widget: the notification comes back to us
        close_widget(w, 0);
    }
    // CH_KEEP means IDA never frees the chooser, but it may still be unwinding the
    // widget that was drawing it, so it is retired rather than deleted here. The next
    // open() disposes of it, by which point that widget is certainly gone.
    m_retired = std::move(m_chooser);
    m_chooser.reset();
}

void ResultsView::open(const ResultsDoc& doc, bool activate) {
    // The chooser retired by the previous open has long outlived its widget.
    m_retired.reset();
    close_window();

    m_doc = doc;
    m_chooser = std::make_unique<Chooser>(*this, m_doc);
    m_selection.clear();
    s_active = this;

    // A STANDALONE chooser window, not a chooser embedded in a form.
    //
    // The form gave us real buttons, but an embedded chooser does not render a
    // dirtree: with the form, IDA drew nameless rows and no folders even though the
    // tree handed to it was provably correct (every row had a label, an address and
    // disassembly text -- that is what the row dump established). Every dirtree
    // chooser IDA itself ships -- Functions, Structures -- is a standalone window, and
    // both embedded-chooser examples in the SDK are flat lists.
    //
    // So the tree wins and the buttons move: the commands live on this window's
    // context menu, and the three that make sense without it under
    // Edit > Plugins > CAPA C++. That costs one click and gains a window that
    // actually shows the namespaces.
    m_chooser->choose();
    m_widget = find_widget(RESULTS_TITLE);
    if (m_widget == nullptr) {
        msg("capa: could not open the results window.\n");
        s_active = nullptr;
        m_chooser.reset();
        return;
    }

    m_plugin.on_results_window_opened(m_widget);
    if (activate) activate_widget(m_widget, true);
}

void ResultsView::set_doc(const ResultsDoc& doc) {
    if (m_chooser == nullptr) return;
    // The window stays; only what is in it changes. Closing and reopening instead
    // would mean destroying a widget from inside one of its own callbacks, and a fresh
    // open_form() before IDA has finished tearing the old one down hands back a widget
    // that is already dying.
    m_doc = doc;
    m_chooser->set_content(m_doc);
    repaint();
}

void ResultsView::refresh_rows() {
    if (m_chooser == nullptr) return;
    m_chooser->refilter();
    repaint();
}

// Make the window show what the chooser now holds.
//
// refresh_field() is the one that matters: the chooser is embedded in a form, and
// refresh_chooser(title) only finds standalone chooser widgets. Both are called
// because the fallback path in open() shows the chooser on its own, and that one IS a
// standalone widget with this title.
void ResultsView::repaint() {
    // A standalone chooser is exactly what refresh_chooser() is for: it looks up a
    // non-modal chooser by title, and this one has a widget of its own to find.
    refresh_chooser(RESULTS_TITLE);
}

void ResultsView::close() {
    close_window();
    m_doc = ResultsDoc{};
}

void ResultsView::forget() {
    // Called while IDA tears the widget down; retire the chooser rather than free it.
    if (s_active == this) s_active = nullptr;
    m_widget = nullptr;
    m_retired = std::move(m_chooser);
    m_chooser.reset();
}

const ResultNode* ResultsView::selected_rule() const {
    return m_chooser != nullptr ? m_chooser->selected_rule() : nullptr;
}

}  // namespace idacapa
