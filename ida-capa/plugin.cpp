#include "plugin.h"

#include "annotate.h"
#include "ida/helpers.h"
#include "pseudocode.h"
#include "settings.h"

namespace idacapa {

const char* const WANTED_NAME = "capa explorer (C++)";

namespace {

const char* const ACTION_ANALYZE = "capacpp:analyze";
const char* const ACTION_SHOW = "capacpp:show";
const char* const ACTION_RULES = "capacpp:rules";
const char* const ACTION_CLEAR = "capacpp:clear";
const char* const ACTION_ANNOTATE = "capacpp:annotate";
const char* const ACTION_ANNOTATE_SEL = "capacpp:annotate_sel";
const char* const ACTION_UNANNOTATE = "capacpp:unannotate";
const char* const ACTION_BY_FUNCTION = "capacpp:by_function";
const char* const ACTION_LIMIT = "capacpp:limit";
const char* const ACTION_SCAN_SYSTEM = "capacpp:scan_system";
const char* const ACTION_FLAT = "capacpp:flat";

// The explorer window's own context menu: everything that acts on the selected row or
// changes what the window shows. Expanding and collapsing is the dirtree's own affair.
const char* const POPUP_ACTIONS[] = {
    ACTION_ANALYZE,     ACTION_ANNOTATE, ACTION_ANNOTATE_SEL, ACTION_UNANNOTATE,
    ACTION_BY_FUNCTION, ACTION_LIMIT,    ACTION_SCAN_SYSTEM,  ACTION_FLAT,
    ACTION_RULES,       ACTION_CLEAR,
};

// The commands a user wants without the explorer window in front of them live in a
// submenu of Edit > Plugins. It is the plugin's only entry there: PLUGIN_HIDE keeps
// IDA from adding its own beside it. "Annotate selected rule only" is not among them:
// it acts on the row under the cursor, so it is only meaningful from the window's
// context menu.
const char* const MENU_NAME = "capacpp:menu";
const char* const MENU_LABEL = "CAPA C++";
const char* const MENU_PATH = "Edit/Plugins/CAPA C++/";
const char* const PLUGINS_PATH = "Edit/Plugins/";
// Where create_menu() puts a menu whose menupath it could not resolve: the menu bar.
const char* const MENUBAR_PATH = "CAPA C++/";
const char* const MENU_ACTIONS[] = {
    ACTION_SHOW,
    ACTION_ANALYZE,
    // Here as well as in the explorer window: the analysis that reports skipped system
    // modules can end with no results, and then there is no window to right-click.
    ACTION_SCAN_SYSTEM,
    ACTION_ANNOTATE,
    ACTION_UNANNOTATE,
};

const int MENU_ACTION_QTY = static_cast<int>(qnumber(MENU_ACTIONS));

// SETMENU_APP appends, so the items keep the order declared above rather than coming
// out reversed. Returns how many took, rather than all-or-nothing: a path that
// accepted some of them has to be remembered as the one they are on, or the caller
// tries the next path and the successful ones end up in two menus at once.
int attach_menu_actions(const char* path) {
    int n = 0;
    for (const char* name : MENU_ACTIONS)
        if (attach_action_to_menu(path, name, SETMENU_APP)) ++n;
    return n;
}

}  // namespace

//-------------------------------------------------------------------------
PluginCtx::PluginCtx() {
    msg("capa: ida-capa loaded (build %s)\n", BUILD_STAMP);
    register_actions();
    hook_event_listener(HT_UI, &m_ui_listener);
    hook_event_listener(HT_IDB, &m_idb_listener);
}

//-------------------------------------------------------------------------
PluginCtx::~PluginCtx() {
    unhook_event_listener(HT_IDB, &m_idb_listener);
    unhook_event_listener(HT_UI, &m_ui_listener);
    shutdown_pseudocode();
    unregister_actions();
}

//-------------------------------------------------------------------------
void PluginCtx::register_actions() {
    // The labels are what the menu shows, so they are kept short; the tooltip beside
    // each one carries the detail.
    register_action(ACTION_DESC_LITERAL_PLUGMOD(ACTION_ANALYZE, "Analyze", &m_analyze, this,
                                                "Alt-F5",
                                                "Find capabilities in this database", -1));
    // Hiding the plugin's own Edit > Plugins entry took with it the one command that
    // reopened the window without re-running the analysis, so it is a menu item now.
    register_action(ACTION_DESC_LITERAL_PLUGMOD(
        ACTION_SHOW, "Show Results", &m_show, this, nullptr,
        "Open the capa explorer window on the results already in this database", -1));

    register_action(ACTION_DESC_LITERAL_PLUGMOD(
        ACTION_BY_FUNCTION, "Show results by function", &m_by_func, this, nullptr,
        "Group the matched rules under the function they were found in", -1));
    register_action(ACTION_DESC_LITERAL_PLUGMOD(
        ACTION_LIMIT, "Limit results to current function", &m_limit, this, nullptr,
        "Show only the rules that matched inside the function under the cursor", -1));
    register_action(ACTION_DESC_LITERAL_PLUGMOD(
        ACTION_SCAN_SYSTEM, "Scan Windows system modules", &m_scan_system, this, nullptr,
        "In a database opened on a process dump, also analyse ntdll, kernel32 and the "
        "rest of System32. Off by default: those are Windows' capabilities, not the "
        "sample's. Other databases are always analysed whole", -1));
    // Without this the tick mark never appears, however update() sets it.
    update_action_checkable(ACTION_BY_FUNCTION, true);
    update_action_checkable(ACTION_LIMIT, true);
    register_action(ACTION_DESC_LITERAL_PLUGMOD(
        ACTION_FLAT, "Show results as a flat list", &m_flat, this, nullptr,
        "List every match with its namespace in a column instead of in folders. Use "
        "this if the folder tree does not render correctly", -1));
    update_action_checkable(ACTION_SCAN_SYSTEM, true);
    update_action_checkable(ACTION_FLAT, true);

    register_action(ACTION_DESC_LITERAL_PLUGMOD(
        ACTION_ANNOTATE, "Annotate Results", &m_annotate, this, nullptr,
        "Colour and comment every address capa matched something at", -1));
    register_action(ACTION_DESC_LITERAL_PLUGMOD(
        ACTION_ANNOTATE_SEL, "Annotate selected rule only", &m_annotate_sel, this, nullptr,
        "Colour and comment only the matches of the rule under the cursor", -1));
    register_action(ACTION_DESC_LITERAL_PLUGMOD(ACTION_UNANNOTATE, "Remove Results",
                                                &m_unannotate, this, nullptr,
                                                "Remove capa's annotations, restoring the "
                                                "colours and comments it changed", -1));

    register_action(ACTION_DESC_LITERAL_PLUGMOD(ACTION_RULES, "capa rules directory...",
                                                &m_rules, this, nullptr,
                                                "Choose which capa rules to load", -1));
    register_action(ACTION_DESC_LITERAL_PLUGMOD(ACTION_CLEAR, "Clear capa results", &m_clear,
                                                this, nullptr,
                                                "Discard the results stored in this database",
                                                -1));

    // Built after the actions exist: attaching one that is not registered yet does
    // nothing.
    ensure_menu();
}

//-------------------------------------------------------------------------
// Edit > Plugins > CAPA C++.
//
// IDA owns the Edit and Plugins menus -- the SDK says as much (kernwin.hpp) -- and
// fills Plugins from the list of loaded plugins, so a submenu placed there can be
// gone by the time anyone looks. Hence: idempotent, run again when the UI reports
// itself ready, and it says in the Output window where the commands ended up, because
// "the menu is not there" is otherwise indistinguishable from "the plugin did not
// load".
void PluginCtx::ensure_menu() {
    // Removes a copy left by an earlier call, along with the items attached to it.
    // False simply means there was none.
    delete_menu(MENU_NAME);
    if (!m_menu_path.empty()) {
        for (const char* name : MENU_ACTIONS) detach_action_from_menu(m_menu_path.c_str(), name);
        m_menu_path.clear();
    }

    // Every branch below reports a partial attach, since a menu missing one of its
    // commands looks like a bug in the command that is missing rather than in this.
    auto took = [&](const char* path, int n, const char* where) {
        m_menu_path = path;
        if (n < MENU_ACTION_QTY)
            msg("capa: only %d of %d commands could be attached to %s.\n", n, MENU_ACTION_QTY,
                where);
    };

    if (create_menu(MENU_NAME, MENU_LABEL, PLUGINS_PATH)) {
        if (int n = attach_menu_actions(MENU_PATH); n > 0) {
            took(MENU_PATH, n, "Edit > Plugins > CAPA C++");
            return;  // the ordinary case; nothing else worth a line in the log
        }
        // create_menu() reports success for a menu it could not place where it was
        // asked, having appended it to the menu bar instead -- in which case the path
        // above does not name it and nothing attached.
        if (int n = attach_menu_actions(MENUBAR_PATH); n > 0) {
            took(MENUBAR_PATH, n, "the \"CAPA C++\" menu");
            msg("capa: Edit > Plugins would not take a submenu; capa's commands are in "
                "the \"%s\" menu on the menu bar.\n",
                MENU_LABEL);
            return;
        }
        delete_menu(MENU_NAME);
    }

    // No submenu anywhere. The commands still have to be reachable, so they go
    // straight into Edit > Plugins beside IDA's own entry for the plugin.
    if (int n = attach_menu_actions(PLUGINS_PATH); n > 0) {
        took(PLUGINS_PATH, n, "Edit > Plugins");
        msg("capa: could not create the \"%s\" submenu; capa's commands are in "
            "Edit > Plugins.\n",
            MENU_LABEL);
        return;
    }
    msg("capa: could not attach capa's commands to any menu. They are on the capa "
        "explorer window's context menu (Alt-F5 opens it).\n");
}

//-------------------------------------------------------------------------
void PluginCtx::unregister_actions() {
    // Detached before the actions go: unregistering one that is still on a menu
    // leaves a dead entry behind. delete_menu() covers the items inside our own
    // submenu, but not the ones a fallback put in a menu IDA owns.
    if (!m_menu_path.empty())
        for (const char* name : MENU_ACTIONS) detach_action_from_menu(m_menu_path.c_str(), name);
    m_menu_path.clear();
    delete_menu(MENU_NAME);
    for (const char* name : {ACTION_ANALYZE, ACTION_SHOW, ACTION_RULES, ACTION_CLEAR,
                             ACTION_ANNOTATE, ACTION_ANNOTATE_SEL, ACTION_UNANNOTATE,
                             ACTION_BY_FUNCTION, ACTION_LIMIT, ACTION_SCAN_SYSTEM,
                             ACTION_FLAT})
        unregister_action(name);
}

//-------------------------------------------------------------------------
void PluginCtx::attach_actions(TWidget* w) {
    if (w == nullptr) return;
    // Attached permanently rather than from ui_populating_widget_popup: every one of
    // these is always relevant in this window.
    for (const char* name : POPUP_ACTIONS) attach_action_to_popup(w, nullptr, name);
}

//-------------------------------------------------------------------------
// Running the plugin (Alt-F5 or Edit > Plugins) opens the results if we already have
// some, and otherwise starts an analysis — the thing a user who just invoked it wants
// in either case.
bool idaapi PluginCtx::run(size_t /*arg*/) {
    if (m_have_results || load_cached())
        show_results();
    else
        analyze();
    return true;
}

//-------------------------------------------------------------------------
bool PluginCtx::load_cached() {
    const std::string dir = rules_dir();
    if (dir.empty()) return false;
    // A cache produced from a different rules directory says nothing about this one.
    if (cached_results_rules_dir() != dir) return false;

    ResultsDoc doc = ResultsDoc::from_json(cached_results());
    if (!doc.valid) {
        // Written by an older build, or corrupt. Drop it so the next run replaces it
        // rather than re-reading it every time.
        clear_cached_results();
        return false;
    }
    if (doc.rules_dir != dir) return false;

    m_doc = std::move(doc);
    m_have_results = true;
    // Say where the results came from: a window full of stale rows is otherwise
    // indistinguishable from a window full of fresh ones.
    msg("capa: loaded %zu cached rule match(es) from this database.\n", m_doc.rules.size());

    // The disassembly comments were saved with the database; the pseudocode markers
    // are generated on the fly, so they have to be put back.
    if (has_annotations()) set_pseudocode_annotations(collect_annotations(m_doc));
    return true;
}

//-------------------------------------------------------------------------
void PluginCtx::analyze() {
    std::string why_not;
    if (!database_is_supported(why_not)) {
        warning("capa: %s", why_not.c_str());
        return;
    }
    if (database_is_dotnet()) {
        // capa analyses managed code with its dnfile backend, which reads CLR
        // metadata. That backend is not ported, and IDA sees only the native stub, so
        // saying so up front beats reporting "no capabilities found".
        if (ask_yn(ASKBTN_NO,
                   "HIDECANCEL\n"
                   "This looks like a .NET assembly.\n\n"
                   "capa analyses managed code with its dnfile backend, which capa-cpp does "
                   "not implement. Only the native stub will be examined, so expect few or "
                   "no results.\n\n"
                   "Analyze anyway?") != ASKBTN_YES)
            return;
    }

    std::string dir = rules_dir();
    if (dir.empty()) {
        dir = ask_rules_dir();
        if (dir.empty()) return;
        set_rules_dir(dir);
    }

    // Whatever is annotated right now describes the previous run.
    const bool was_annotated = has_annotations();

    if (!do_analysis(dir)) return;
    if (m_doc.empty()) {
        if (was_annotated) remove_annotations_action();
        info("capa found no capabilities in this database.");
        return;
    }
    show_results();
    if (was_annotated) annotate_all();
}

//-------------------------------------------------------------------------
// The analysis itself, once the rules directory is settled. Returns false if it
// failed or the user cancelled, having already said so.
bool PluginCtx::do_analysis(const std::string& dir) {
    ResultsDoc doc;
    std::string error;
    if (!run_analysis(dir, doc, error)) {
        if (!error.empty()) {
            warning("capa: %s", error.c_str());
            msg("capa: %s\n", error.c_str());
        } else {
            msg("capa: analysis cancelled.\n");
        }
        return false;
    }

    m_doc = std::move(doc);
    m_have_results = true;
    set_cached_results(m_doc.to_json(), dir);

    msg("capa: %zu rule(s) matched over %zu function(s); %zu rule(s) loaded from %s\n",
        m_doc.match_count, m_doc.function_count, m_doc.rules_loaded, dir.c_str());
    return true;
}

//-------------------------------------------------------------------------
// Run the rules over the database again without asking anything: for picking up rule
// edits, or results that have gone stale against a database you have since renamed and
// re-analysed.
void PluginCtx::reanalyze() {
    const std::string dir = rules_dir();
    if (dir.empty()) {
        analyze();  // nothing configured yet; that path asks for a rules directory
        return;
    }

    std::string why_not;
    if (!database_is_supported(why_not)) {
        warning("capa: %s", why_not.c_str());
        return;
    }
    // The .NET warning is not repeated: reaching here means an analysis has already
    // been run against this database, so it has been answered once.

    // Annotations describe the results that produced them. If any are in place, put
    // them back from the new results rather than leaving the old ones behind.
    const bool was_annotated = has_annotations();

    if (!do_analysis(dir)) return;

    if (m_doc.empty()) {
        if (was_annotated) remove_annotations_action();
        // Emptied rather than closed: this runs from the window's own Reanalyze
        // button, and tearing a widget down from inside its own callback is the kind
        // of thing that only sometimes survives.
        m_results.set_doc(m_doc);
        m_details.show_message("capa found no capabilities in this database.",
                               /*activate=*/false);
        info("capa found no capabilities in this database.");
        return;
    }

    show_results();
    if (was_annotated) annotate_all();
}

//-------------------------------------------------------------------------
// Put back what a previous session left in this database. Runs at most once per
// database: reading the cache is cheap, but re-reading it on every notification is
// pointless, and rebuilding the pseudocode index needs the address map to be up.
void PluginCtx::restore_session() {
    if (m_restored) return;
    m_restored = true;

    // Only worth doing if this database has annotations to put back — load_cached()
    // reinstates the pseudocode markers as a side effect when it finds them.
    if (!has_annotations()) return;
    if (!m_have_results) load_cached();
}

//-------------------------------------------------------------------------
void PluginCtx::refresh_view(bool activate) {
    ResultsDoc view = by_function() ? group_by_function(m_doc) : m_doc;
    if (m_results.is_open()) {
        // The window stays put; only its contents change.
        m_results.set_doc(view);
        return;
    }
    // The details pane goes up first so the explorer can dock beside it and so the
    // first row's selection has somewhere to land.
    m_details.show_message("Select a match to see why it matched.", /*activate=*/false);
    m_results.open(view, activate);
}

//-------------------------------------------------------------------------
// Called by ResultsView every time it builds a window, including the rebuilds it
// schedules for itself.
void PluginCtx::on_results_window_opened(TWidget* w) {
    attach_actions(w);
    set_dock_pos(DETAILS_TITLE, RESULTS_TITLE, DP_RIGHT);
}

//-------------------------------------------------------------------------
void PluginCtx::show_results() {
    if (!m_have_results && !load_cached()) {
        analyze();
        return;
    }
    if (m_doc.empty()) {
        info("capa found no capabilities in this database.");
        return;
    }
    refresh_view(/*activate=*/true);
}

//-------------------------------------------------------------------------
void PluginCtx::choose_rules_dir() {
    std::string dir = ask_rules_dir();
    if (dir.empty()) return;
    set_rules_dir(dir);
    // Results from the previous rules say nothing about the new ones.
    clear_results();
    msg("capa: rules directory set to %s\n", dir.c_str());
}

//-------------------------------------------------------------------------
void PluginCtx::clear_results() {
    m_results.close();
    m_details.close();
    // Annotations describe results that are about to be discarded. Leaving them would
    // put unexplained comments in the database and, worse, leave has_annotations()
    // true against a cache that no longer exists — so nothing could restore them.
    if (has_annotations()) {
        remove_annotations();
        set_pseudocode_annotations(AnnotationMap{});
        refresh_idaview_anyway();
    }
    m_doc = ResultsDoc{};
    m_have_results = false;
    clear_cached_results();
}

//-------------------------------------------------------------------------
void PluginCtx::annotate_all() {
    if (!m_have_results && !load_cached()) {
        info("capa: run an analysis first.");
        return;
    }
    AnnotationStats s = annotate(m_doc);
    // The decompiler shows none of the disassembly's comments, so the same findings go
    // into the pseudocode by a separate route.
    set_pseudocode_annotations(collect_annotations(m_doc));
    msg("capa: annotated %zu address(es) with %zu comment(s).\n", s.addresses, s.comments);
    if (s.addresses == 0) info("capa: nothing to annotate.");
    refresh_idaview_anyway();
}

//-------------------------------------------------------------------------
void PluginCtx::annotate_selected() {
    // The node belongs to the window's own copy of the results, which in the
    // grouped-by-function view holds only the matches from one function — so this
    // annotates exactly what the selected row stands for.
    const ResultNode* rule = m_results.selected_rule();
    if (rule == nullptr) {
        info("capa: select a match in the capa explorer window first.");
        return;
    }

    AnnotationStats s = annotate(m_doc, rule);
    set_pseudocode_annotations(collect_annotations(m_doc, rule));
    msg("capa: annotated %zu address(es) for '%s'.\n", s.addresses, rule->info.c_str());
    if (s.addresses == 0) info("capa: that rule has no addresses to annotate.");
    refresh_idaview_anyway();
}

//-------------------------------------------------------------------------
void PluginCtx::remove_annotations_action() {
    if (!has_annotations()) {
        info("capa: there are no capa annotations in this database.");
        return;
    }
    std::size_t n = remove_annotations();
    set_pseudocode_annotations(AnnotationMap{});
    msg("capa: removed annotations from %zu address(es).\n", n);
    refresh_idaview_anyway();
}

//-------------------------------------------------------------------------
bool PluginCtx::by_function() const { return show_results_by_function(); }
bool PluginCtx::limit_to_function() const { return limit_to_current_function(); }
bool PluginCtx::scan_system() const { return scan_system_modules(); }
bool PluginCtx::flat() const { return flat_results(); }

//-------------------------------------------------------------------------
// Purely a display choice, so whatever is already loaded is simply rebuilt.
void PluginCtx::toggle_flat_results() {
    set_flat_results(!flat());
    if (m_results.is_open() && m_have_results) refresh_view(/*activate=*/true);
}

//-------------------------------------------------------------------------
// Unlike the two view toggles, this one changes what gets ANALYSED, not what gets
// displayed — so the results on screen are now stale rather than merely regrouped.
// Say so instead of silently leaving them up.
void PluginCtx::toggle_scan_system_modules() {
    set_scan_system_modules(!scan_system());
    if (m_have_results)
        info("capa: system modules will %s the next analysis.\n"
             "Re-run Analyze (Alt-F5) to apply this.",
             scan_system() ? "be included in" : "be excluded from");
}

//-------------------------------------------------------------------------
void PluginCtx::toggle_by_function() {
    set_show_results_by_function(!by_function());
    // Regrouping changes the tree itself, so the window is rebuilt rather than
    // refreshed: the nodes the chooser held pointers into are gone.
    if (m_results.is_open() && m_have_results) refresh_view(/*activate=*/true);
}

//-------------------------------------------------------------------------
void PluginCtx::toggle_limit_to_function() {
    set_limit_to_current_function(!limit_to_function());
    // Remember which function the filter is now showing. Without this the cursor
    // handler compares against a stale value and can decide there is nothing to do
    // while the window shows some other function's matches.
    m_limit_func_ea =
        limit_to_function() ? capa::ida::func_start_of(get_screen_ea()) : BADADDR;
    m_results.refresh_rows();
}

//-------------------------------------------------------------------------
// UI and database notifications are delivered through two listeners rather than one.
// ui_notification_t and idb_event::event_code_t are separate, dense, zero-based enums,
// so their values collide wholesale — `closebase` is 0, and so is the first ui_
// notification. A single switch over both cannot tell them apart, and would act on a
// va_list belonging to something else entirely.
ssize_t idaapi PluginCtx::on_ui_event(ssize_t code, va_list va) {
    switch (code) {
        case ui_widget_invisible: {
            // IDA is destroying a widget: drop our pointer before it dangles.
            TWidget* w = va_arg(va, TWidget*);
            if (m_results.owns(w))
                m_results.forget();
            else if (m_details.owns(w))
                m_details.forget();
            break;
        }

        case ui_ready_to_run:
            // The database is up. The disassembly's colours and comments were saved
            // with it, but the pseudocode markers are generated on the fly and would
            // otherwise stay missing until the user next ran the plugin.
            restore_session();
            // And the menus are up -- definitively, this time. Our submenu was built
            // while IDA was still assembling Edit > Plugins, which is exactly when it
            // rebuilds that menu from the plugin list and drops anything else in it.
            ensure_menu();
            break;

        case ui_screen_ea_changed: {
            // "Limit to current function" is relative to where the cursor is, so the
            // row list has to follow the cursor — but only when the cursor moved for a
            // reason that matters.
            if (!limit_to_function() || !m_results.is_open()) break;

            // Selecting a row in the results window moves the screen ea itself. Acting
            // on that would refilter the list out from under the arrow key that caused
            // it, so navigation inside our own window does not count.
            if (m_results.owns(get_current_widget())) break;

            // Rebuilding is not free; moving within one function changes nothing.
            ea_t fea = capa::ida::func_start_of(get_screen_ea());
            if (fea == m_limit_func_ea) break;
            m_limit_func_ea = fea;

            m_results.refresh_rows();
            break;
        }
    }
    return 0;
}

//-------------------------------------------------------------------------
ssize_t idaapi PluginCtx::on_idb_event(ssize_t code, va_list /*va*/) {
    switch (code) {
        case idb_event::auto_empty_finally:
            // Belt and braces: ui_ready_to_run fires once per IDA session, so a second
            // database opened in the same session needs this one instead.
            restore_session();
            break;

        case idb_event::closebase:
            // The window points into m_doc, which is about to go away.
            m_results.close();
            m_details.close();
            set_pseudocode_annotations(AnnotationMap{});
            m_doc = ResultsDoc{};
            m_have_results = false;
            m_restored = false;
            break;
    }
    return 0;
}

}  // namespace idacapa

//-------------------------------------------------------------------------
static plugmod_t* idaapi init() { return new idacapa::PluginCtx; }

//-------------------------------------------------------------------------
plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    // PLUGIN_MULTI: init() returns a plugmod_t.
    // PLUGIN_HIDE: keep IDA's automatic "capa explorer (C++)" entry out of
    // Edit > Plugins. Everything it did is in our own submenu there, and the name
    // below is still what IDA calls the plugin everywhere else. The plugin is loaded
    // exactly as before; run() simply has no menu entry of its own any more.
    PLUGIN_MULTI | PLUGIN_HIDE,
    init,
    nullptr,  // term: must be null for PLUGIN_MULTI
    nullptr,  // run:  must be null for PLUGIN_MULTI
    "Find capabilities in a binary with capa",
    "Runs capa's rule set against the open database and shows which capabilities\n"
    "matched, where, and why. Point it at a copy of capa's rules/ directory.",
    idacapa::WANTED_NAME,
    ""  // hotkeys come from the registered actions
};
