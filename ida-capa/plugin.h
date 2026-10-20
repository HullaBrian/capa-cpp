// The ida-capa plugin object.
//
// It is both the plugmod_t IDA gets back from init() and the listener for the
// database notifications we care about, so there is one owner for the analysis
// results and the window that displays them.
#pragma once

#include "pch.h"

#include "analysis.h"
#include "view_details.h"
#include "view_results.h"

namespace idacapa {

// Stamped into the binary at compile time and printed when the plugin loads.
//
// Windows keeps ida-capa.dll open for as long as IDA is running, so copying a fresh
// build over it while IDA is up does not fail loudly -- it just does not happen, and
// the next run behaves exactly like the build before. Every symptom then looks like a
// bug that was already fixed. This one line settles which binary is actually loaded.
inline constexpr const char* BUILD_STAMP = __DATE__ " " __TIME__;

extern const char* const WANTED_NAME;

class PluginCtx : public plugmod_t {
public:
    PluginCtx();
    ~PluginCtx() override;

    bool idaapi run(size_t arg) override;

    // Delivered by the two listeners below. Kept apart because ui_notification_t and
    // idb_event::event_code_t are independent dense enums whose values collide.
    ssize_t on_ui_event(ssize_t code, va_list va);
    ssize_t on_idb_event(ssize_t code, va_list va);

    // --- actions ----------------------------------------------------------
    void analyze();
    void reanalyze();
    void show_results();
    void choose_rules_dir();
    void clear_results();

    void annotate_all();
    void annotate_selected();
    void remove_annotations_action();

    void toggle_by_function();
    void toggle_limit_to_function();
    void toggle_scan_system_modules();
    void toggle_flat_results();

    // --- state read by the checkable actions ------------------------------
    bool by_function() const;
    bool limit_to_function() const;
    bool scan_system() const;
    bool flat() const;

    DetailsView& details() { return m_details; }

    // ResultsView calls this each time it builds its window.
    void on_results_window_opened(TWidget* w);

private:
    void register_actions();
    void unregister_actions();
    void attach_actions(TWidget* w);

    // (Re)build the Edit > Plugins > CAPA C++ submenu. Idempotent.
    void ensure_menu();

    // Load results from the database cache into m_doc, if there are any and they
    // still match the configured rules directory.
    bool load_cached();

    // The analysis itself, once the rules directory is settled.
    bool do_analysis(const std::string& dir);

    // Re-open the window from m_doc, honouring the "by function" toggle.
    void refresh_view(bool activate);

    // Reinstate whatever a previous session left in this database (currently the
    // pseudocode markers, which are not saved with it). Idempotent.
    void restore_session();

    ResultsDoc m_doc;      // as analysed, always "by program"
    bool m_have_results = false;
    // The function the "limit" filter is currently showing, so a cursor move inside
    // that same function does not trigger a rebuild.
    ea_t m_limit_func_ea = BADADDR;
    // Set once the database is far enough along to read the netnode and resolve
    // addresses; see on_event().
    bool m_restored = false;
    // The menu path the commands are actually attached to, which is not always the
    // one they were asked to go to; empty when nothing took them. Kept so they can be
    // detached from the right place.
    std::string m_menu_path;
    // Whether this database was opened on a process minidump. Fixed for the plugin's
    // lifetime (one PluginCtx per database), and the only kind of database the
    // system-module toggle means anything for.
    bool m_is_dump = false;

    ResultsView m_results{*this};
    DetailsView m_details;

    // One listener per hook type, so a notification is always interpreted against the
    // enum it actually came from.
    struct UiListener : public event_listener_t {
        explicit UiListener(PluginCtx& p) : plugin(p) {}
        ssize_t idaapi on_event(ssize_t code, va_list va) override {
            return plugin.on_ui_event(code, va);
        }
        PluginCtx& plugin;
    };
    struct IdbListener : public event_listener_t {
        explicit IdbListener(PluginCtx& p) : plugin(p) {}
        ssize_t idaapi on_event(ssize_t code, va_list va) override {
            return plugin.on_idb_event(code, va);
        }
        PluginCtx& plugin;
    };
    UiListener m_ui_listener{*this};
    IdbListener m_idb_listener{*this};

    struct ActionHandler : public action_handler_t {
        using Fn = void (PluginCtx::*)();
        ActionHandler(PluginCtx& p, Fn fn) : plugin(p), fn(fn) {}
        int idaapi activate(action_activation_ctx_t*) override {
            (plugin.*fn)();
            return 1;
        }
        action_state_t idaapi update(action_update_ctx_t*) override {
            return AST_ENABLE_ALWAYS;
        }
        PluginCtx& plugin;
        Fn fn;
    };

    // Same, but ticks itself in the menu. IDA only reads the tick when the action is
    // updated, so that is where it has to be set.
    struct ToggleHandler : public action_handler_t {
        using Fn = void (PluginCtx::*)();
        using Get = bool (PluginCtx::*)() const;
        ToggleHandler(PluginCtx& p, Fn fn, Get get) : plugin(p), fn(fn), get(get) {}
        int idaapi activate(action_activation_ctx_t*) override {
            (plugin.*fn)();
            return 1;
        }
        action_state_t idaapi update(action_update_ctx_t* ctx) override {
            update_action_checked(ctx->action, (plugin.*get)());
            return AST_ENABLE_ALWAYS;
        }
        PluginCtx& plugin;
        Fn fn;
        Get get;
    };

    ActionHandler m_analyze{*this, &PluginCtx::analyze};
    ActionHandler m_show{*this, &PluginCtx::show_results};
    ActionHandler m_rules{*this, &PluginCtx::choose_rules_dir};
    ActionHandler m_clear{*this, &PluginCtx::clear_results};
    ActionHandler m_annotate{*this, &PluginCtx::annotate_all};
    ActionHandler m_annotate_sel{*this, &PluginCtx::annotate_selected};
    ActionHandler m_unannotate{*this, &PluginCtx::remove_annotations_action};
    ToggleHandler m_by_func{*this, &PluginCtx::toggle_by_function, &PluginCtx::by_function};
    ToggleHandler m_limit{*this, &PluginCtx::toggle_limit_to_function,
                          &PluginCtx::limit_to_function};
    ToggleHandler m_scan_system{*this, &PluginCtx::toggle_scan_system_modules,
                                &PluginCtx::scan_system};
    ToggleHandler m_flat{*this, &PluginCtx::toggle_flat_results, &PluginCtx::flat};
};

}  // namespace idacapa
