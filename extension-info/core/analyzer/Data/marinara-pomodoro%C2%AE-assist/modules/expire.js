(function(o) {
    function t(t) {
        for (var r, a, s = t[0], p = t[1], c = t[2], u = 0, l = []; u < s.length; u++) a = s[u], n[a] && l.push(n[a][0]), n[a] = 0;
        for (r in p) Object.prototype.hasOwnProperty.call(p, r) && (o[r] = p[r]);
        d && d(t);
        while (l.length) l.shift()();
        return i.push.apply(i, c || []), e()
    }

    function e() {
        for (var o, t = 0; t < i.length; t++) {
            for (var e = i[t], r = !0, s = 1; s < e.length; s++) {
                var p = e[s];
                0 !== n[p] && (r = !1)
            }
            r && (i.splice(t--, 1), o = a(a.s = e[0]))
        }
        return o
    }
    var r = {},
        n = {
            expire: 0
        },
        i = [];

    function a(t) {
        if (r[t]) return r[t].exports;
        var e = r[t] = {
            i: t,
            l: !1,
            exports: {}
        };
        return o[t].call(e.exports, e, e.exports, a), e.l = !0, e.exports
    }
    a.m = o, a.c = r, a.d = function(o, t, e) {
        a.o(o, t) || Object.defineProperty(o, t, {
            enumerable: !0,
            get: e
        })
    }, a.r = function(o) {
        "undefined" !== typeof Symbol && Symbol.toStringTag && Object.defineProperty(o, Symbol.toStringTag, {
            value: "Module"
        }), Object.defineProperty(o, "__esModule", {
            value: !0
        })
    }, a.t = function(o, t) {
        if (1 & t && (o = a(o)), 8 & t) return o;
        if (4 & t && "object" === typeof o && o && o.__esModule) return o;
        var e = Object.create(null);
        if (a.r(e), Object.defineProperty(e, "default", {
                enumerable: !0,
                value: o
            }), 2 & t && "string" != typeof o)
            for (var r in o) a.d(e, r, function(t) {
                return o[t]
            }.bind(null, r));
        return e
    }, a.n = function(o) {
        var t = o && o.__esModule ? function() {
            return o["default"]
        } : function() {
            return o
        };
        return a.d(t, "a", t), t
    }, a.o = function(o, t) {
        return Object.prototype.hasOwnProperty.call(o, t)
    }, a.p = "/modules/";
    var s = window["webpackJsonp"] = window["webpackJsonp"] || [],
        p = s.push.bind(s);
    s.push = t, s = s.slice();
    for (var c = 0; c < s.length; c++) t(s[c]);
    var d = p;
    i.push([1, "chunk-vendors", "chunk-common"]), e()
})({
    1: function(o, t, e) {
        o.exports = e("47cf")
    },
    "47cf": function(o, t, e) {
        "use strict";
        e.r(t);
        e("097d");
        var r = e("2b0e"),
            n = function() {
                var o = this,
                    t = o.$createElement,
                    e = o._self._c || t;
                return o.show ? e("div", {
                    staticClass: "dialog"
                }, [e("h1", [o._v(o._s(o.title))]), o._v(" "), e("div", [e("p", [o._v(o._s(o.message))])]), o._v(" "), e("button", {
                    staticClass: "button start-session",
                    class: o.phase,
                    on: {
                        click: function(t) {
                            return t.preventDefault(), o.startSession(t)
                        }
                    }
                }, [o._v("\n    " + o._s(o.action) + "\n  ")]), o._v(" "), e("div", {
                    staticClass: "pomodoros-today"
                }, [e("p", {
                    staticClass: "pomodoros"
                }, o._l(new Array(o.pomodoroCount), function(o) {
                    return e("i", {
                        staticClass: "icon-circle"
                    })
                })), o._v(" "), e("p", [o._v(o._s(o.M.completed_today))]), o._v(" "), e("button", {
                    staticClass: "view-history",
                    on: {
                        click: function(t) {
                            return t.preventDefault(), o.showHistoryPage(t)
                        }
                    }
                }, [o._v(o._s(o.M.view_history))])])]) : o._e()
            },
            i = [],
            a = e("0567"),
            s = e("dcb2"),
            p = e("b376"),
            c = {
                data() {
                    return {
                        show: !1,
                        title: "",
                        action: "",
                        message: "",
                        phase: "",
                        pomodoroCount: 0
                    }
                },
                async created() {
                    document.title = `${a["a"].expire_title} - ${a["a"].app_name_short}`, document.body.addEventListener("keypress", this.onKeyPress);
                    let {
                        title: o,
                        action: t,
                        pomodoros: e,
                        messages: r,
                        phase: n
                    } = await p["a"].once.getProperties();
                    this.show = !0, this.title = o, this.action = t, this.pomodoroCount = e, this.message = r.filter(o => o && o.trim()).join(" – "), this.phase = n
                },
                beforeDestroy() {
                    document.body.removeEventListener("keypress", this.onKeyPress)
                },
                methods: {
                    startSession() {
                        s["e"].once.start()
                    },
                    showHistoryPage() {
                        s["c"].once.showHistoryPage()
                    },
                    onKeyPress(o) {
                        "Enter" === o.key && this.startSession()
                    }
                }
            },
            d = c,
            u = (e("b1fd"), e("2877")),
            l = Object(u["a"])(d, n, i, !1, null, null, null),
            f = l.exports;
        r["a"].config.productionTip = !1, r["a"].config.devtools = !1, r["a"].mixin({
            computed: {
                M() {
                    return a["a"]
                }
            }
        }), new r["a"]({
            render: o => o(f)
        }).$mount("#app")
    },
    "72d6": function(o, t, e) {
        var r = e("87b4");
        "string" === typeof r && (r = [
            [o.i, r, ""]
        ]), r.locals && (o.exports = r.locals);
        var n = e("499e").default;
        n("1afc7274", r, !0, {
            sourceMap: !1,
            shadowMode: !1
        })
    },
    "87b4": function(o, t, e) {
        t = o.exports = e("2350")(!1), t.i(e("7906"), ""), t.i(e("57d7"), ""), t.push([o.i, "body,button,html{font-family:Source Sans Pro,sans-serif}body,html{height:100%;padding:0;margin:0}.dialog,body{background:#fff}.dialog{position:relative;padding:50px 0;top:15%;text-align:center}.dialog h1{margin:0 auto 15px auto;padding-bottom:15px;border-bottom:1px solid #ddd;font-weight:400;font-size:32px;width:500px}.dialog p{color:#222;font-size:18px;margin:0 0 30px 0}.dialog .pomodoros-today p{margin-bottom:15px}.button{margin:0;font-size:20px;-webkit-user-select:none;-webkit-tap-highlight-color:rgba(0,0,0,0);-webkit-touch-callout:none;outline:none;display:inline-block;background-color:#fff;color:#646464;cursor:pointer;border:0;border-radius:50px;padding:15px 45px;text-align:center;text-decoration:none!important;background:#00aeff;background:-webkit-gradient(left top,left bottom,color-stop(0,#00aeff),color-stop(92%,#00aeff),color-stop(100%,#0090ea));background:-webkit-linear-gradient(top,#00aeff,#00aeff 92%,#0090ea);color:#fff;transition:box-shadow .2s cubic-bezier(.4,0,.2,1),background .1s linear;z-index:1;position:relative}.button.break,.button.long-break,.button.short-break{background:#0a0;box-shadow:0 15px 8px -10px rgba(0,170,0,.33);color:#fff}.button.break:hover,.button.long-break:hover,.button.short-break:hover{background:#0b0}.button.focus{background:#d00;box-shadow:0 15px 8px -10px rgba(187,0,0,.33);color:#fff}.button.focus:hover{background:#e00}.button:active{box-shadow:none;transition-delay:0s}.button::not(.focus):not(.break):not(.short-break):not(.long-break){display:none}.start-session{margin-top:10px}.pomodoros-today{margin-top:110px;line-height:100%}.view-history{cursor:pointer;font-size:15px;background:#fff;color:#555;border:1px solid #555;border-radius:3px;padding:8px 25px;margin:5px 0 0 0;outline:0!important;border-radius:35px}.view-history:hover{color:#a00;border:1px solid #a00;text-decoration:none}.pomodoros i{font-size:35px;margin-top:7px;color:#d00!important;text-shadow:0 2px 2px rgba(200,0,0,.3)}.pomodoros:empty~*{display:none}", ""])
    },
    b1fd: function(o, t, e) {
        "use strict";
        var r = e("72d6"),
            n = e.n(r);
        n.a
    }
});