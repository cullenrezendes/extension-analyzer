(function(t) {
    function e(e) {
        for (var n, o, r = e[0], l = e[1], c = e[2], d = 0, p = []; d < r.length; d++) o = r[d], i[o] && p.push(i[o][0]), i[o] = 0;
        for (n in l) Object.prototype.hasOwnProperty.call(l, n) && (t[n] = l[n]);
        u && u(e);
        while (p.length) p.shift()();
        return a.push.apply(a, c || []), s()
    }

    function s() {
        for (var t, e = 0; e < a.length; e++) {
            for (var s = a[e], n = !0, r = 1; r < s.length; r++) {
                var l = s[r];
                0 !== i[l] && (n = !1)
            }
            n && (a.splice(e--, 1), t = o(o.s = s[0]))
        }
        return t
    }
    var n = {},
        i = {
            countdown: 0
        },
        a = [];

    function o(e) {
        if (n[e]) return n[e].exports;
        var s = n[e] = {
            i: e,
            l: !1,
            exports: {}
        };
        return t[e].call(s.exports, s, s.exports, o), s.l = !0, s.exports
    }
    o.m = t, o.c = n, o.d = function(t, e, s) {
        o.o(t, e) || Object.defineProperty(t, e, {
            enumerable: !0,
            get: s
        })
    }, o.r = function(t) {
        "undefined" !== typeof Symbol && Symbol.toStringTag && Object.defineProperty(t, Symbol.toStringTag, {
            value: "Module"
        }), Object.defineProperty(t, "__esModule", {
            value: !0
        })
    }, o.t = function(t, e) {
        if (1 & e && (t = o(t)), 8 & e) return t;
        if (4 & e && "object" === typeof t && t && t.__esModule) return t;
        var s = Object.create(null);
        if (o.r(s), Object.defineProperty(s, "default", {
                enumerable: !0,
                value: t
            }), 2 & e && "string" != typeof t)
            for (var n in t) o.d(s, n, function(e) {
                return t[e]
            }.bind(null, n));
        return s
    }, o.n = function(t) {
        var e = t && t.__esModule ? function() {
            return t["default"]
        } : function() {
            return t
        };
        return o.d(e, "a", e), e
    }, o.o = function(t, e) {
        return Object.prototype.hasOwnProperty.call(t, e)
    }, o.p = "/modules/";
    var r = window["webpackJsonp"] = window["webpackJsonp"] || [],
        l = r.push.bind(r);
    r.push = e, r = r.slice();
    for (var c = 0; c < r.length; c++) e(r[c]);
    var u = l;
    a.push([2, "chunk-vendors", "chunk-common"]), s()
})({
    "1d37": function(t, e, s) {
        var n = s("5f1e");
        "string" === typeof n && (n = [
            [t.i, n, ""]
        ]), n.locals && (t.exports = n.locals);
        var i = s("499e").default;
        i("61cc26dc", n, !0, {
            sourceMap: !1,
            shadowMode: !1
        })
    },
    2: function(t, e, s) {
        t.exports = s("dade")
    },
    28770: function(t, e, s) {
        var n = s("995c");
        "string" === typeof n && (n = [
            [t.i, n, ""]
        ]), n.locals && (t.exports = n.locals);
        var i = s("499e").default;
        i("6112654d", n, !0, {
            sourceMap: !1,
            shadowMode: !1
        })
    },
    "5f1e": function(t, e, s) {
        e = t.exports = s("2350")(!1), e.push([t.i, "@keyframes blink{0%{opacity:1}49%{opacity:1}50%{opacity:0}to{opacity:0}}.timer{position:relative}.timer,.timer svg{height:100%;width:100%}.timer svg path.duration{stroke:#ddd;stroke-width:3px;fill:none}.timer svg path.elapsed{stroke-width:3px;stroke-linecap:round;fill:none}.timer .overlay{position:absolute;left:0;top:0;bottom:0;right:0;display:flex;flex-direction:column;justify-content:center;align-items:center}.timer .overlay .time{font-weight:600;color:#ccc}.timer .overlay .time.enabled{color:#333}.timer .overlay .time.paused{animation:blink 1s linear infinite}.timer .controls{z-index:2;margin:3vmin 0}.timer .controls button{color:#bbb;margin:0;padding:0;border:0;outline:0;background:transparent;cursor:pointer;transition:color .15s ease}.timer .controls button:hover{color:#333}.timer .controls button svg{width:7vmin;height:7vmin}.timer .controls .placeholder{visibility:hidden}", ""])
    },
    "61c8": function(t, e, s) {
        "use strict";
        var n = s("1d37"),
            i = s.n(n);
        i.a
    },
    6568: function(t, e, s) {
        "use strict";
        var n = s("65e0"),
            i = s.n(n);
        i.a
    },
    "65e0": function(t, e, s) {
        var n = s("7882");
        "string" === typeof n && (n = [
            [t.i, n, ""]
        ]), n.locals && (t.exports = n.locals);
        var i = s("499e").default;
        i("6c6f8534", n, !0, {
            sourceMap: !1,
            shadowMode: !1
        })
    },
    7882: function(t, e, s) {
        e = t.exports = s("2350")(!1), e.i(s("57d7"), ""), e.push([t.i, "body{margin:0;padding:0}.countdown{display:flex;height:100vh;max-width:100vw;justify-content:center;align-items:center}.countdown .timer{height:90%;width:90%}.countdown .timer svg path.elapsed{stroke:#42d}.countdown .timer.focus svg path.elapsed{stroke:#d42}.countdown .timer.break svg path.elapsed{stroke:#5a4}button.nav{flex:0 0 150px;outline:0!important;background:transparent;font-size:18px;cursor:pointer;color:#555;border:0;text-decoration:none;position:absolute;display:none;align-items:center}button.nav:hover{color:#a00}button.nav span{display:none}button.nav svg{width:28px;height:28px}@media (min-width:250px){button.nav{display:flex}}@media (min-width:600px){button.nav span{display:inherit}}.settings{left:10px;bottom:10px}@media (min-width:400px){.settings{left:20px;bottom:20px}}.settings svg{margin-right:10px}.history{right:10px;bottom:10px}@media (min-width:400px){.history{right:20px;bottom:20px}}.history svg{margin-left:10px}", ""])
    },
    "995c": function(t, e, s) {
        e = t.exports = s("2350")(!1), e.push([t.i, "div[data-v-7c844d74]{display:contents}[data-v-7c844d74] svg{fill:currentColor}", ""])
    },
    cd60: function(t, e, s) {
        "use strict";
        var n = s("28770"),
            i = s.n(n);
        i.a
    },
    dade: function(t, e, s) {
        "use strict";
        s.r(e);
        s("097d");
        var n, i, a = s("2b0e"),
            o = function() {
                var t = this,
                    e = t.$createElement,
                    s = t._self._c || e;
                return s("div", [s("div", {
                    staticClass: "countdown"
                }, [s("Timer", {
                    class: t.timerClass,
                    attrs: {
                        state: t.state,
                        duration: t.duration,
                        elapsed: t.elapsed,
                        enabled: t.hasTime
                    },
                    on: {
                        pause: t.onPause,
                        resume: t.onResume,
                        restart: t.onRestart
                    }
                })], 1), t._v(" "), s("button", {
                    staticClass: "settings nav",
                    attrs: {
                        title: t.M.settings
                    },
                    on: {
                        click: t.showSettings
                    }
                }, [s("Sprite", {
                    attrs: {
                        src: "/images/settings.svg"
                    }
                }), t._v(" "), s("span", [t._v(t._s(t.M.settings))])], 1), t._v(" "), s("button", {
                    staticClass: "history nav",
                    attrs: {
                        title: t.M.view_history
                    },
                    on: {
                        click: t.showHistory
                    }
                }, [s("span", [t._v(t._s(t.M.view_history))]), t._v(" "), s("Sprite", {
                    attrs: {
                        src: "/images/history.svg"
                    }
                })], 1)])
            },
            r = [],
            l = s("0daf"),
            c = s("dcb2"),
            u = s("583d"),
            d = {
                data() {
                    return {
                        elapsed: null,
                        state: null,
                        phase: null,
                        duration: null,
                        checkpointElapsed: null,
                        checkpointStartAt: null,
                        timeInterval: null,
                        pomodoroClient: new c["e"]
                    }
                },
                async mounted() {
                    const t = ({
                        state: t,
                        phase: e,
                        duration: s,
                        checkpointElapsed: n,
                        checkpointStartAt: i
                    }) => {
                        this.state = t, this.phase = e, this.duration = s, this.checkpointElapsed = n, this.checkpointStartAt = i
                    };
                    this.pomodoroClient.on("start", t), this.pomodoroClient.on("resume", t), this.pomodoroClient.on("stop", t), this.pomodoroClient.on("pause", t), this.pomodoroClient.on("expire", t);
                    let e = await this.pomodoroClient.getStatus();
                    t(e), this.updateElapsed()
                },
                beforeDestroy() {
                    clearInterval(this.timeInterval), this.pomodoroClient.dispose()
                },
                computed: {
                    remaining() {
                        return this.duration - this.elapsed
                    },
                    remainingSeconds() {
                        return Math.ceil(this.remaining)
                    },
                    elapsedSeconds() {
                        return Math.ceil(this.elapsed)
                    },
                    hasTime() {
                        return null != this.duration && null != this.checkpointStartAt && null != this.checkpointElapsed
                    }
                },
                watch: {
                    checkpointStartAt() {
                        this.updateElapsed()
                    },
                    checkpointElapsed() {
                        this.updateElapsed()
                    },
                    duration() {
                        this.updateElapsed()
                    },
                    state(t) {
                        clearInterval(this.timeInterval);
                        let e = Object(u["a"])(1e3 / (2 * Math.PI / this.duration * 500), 20, 1e3);
                        t == l["c"].Running ? this.timeInterval = setInterval(() => this.updateElapsed(), e) : this.updateElapsed()
                    }
                },
                methods: {
                    updateElapsed() {
                        if (!this.hasTime) return void(this.elapsed = 0);
                        let t = this.checkpointElapsed;
                        this.checkpointStartAt && this.state == l["c"].Running && (t += (Date.now() - this.checkpointStartAt) / 1e3), this.elapsed = Math.min(this.duration, t);
                        let e = Math.ceil(this.duration - this.elapsed);
                        0 == e && clearInterval(this.timeInterval)
                    }
                }
            },
            p = d,
            h = s("2877"),
            m = Object(h["a"])(p, n, i, !1, null, null, null),
            v = m.exports,
            g = function() {
                var t = this,
                    e = t.$createElement,
                    s = t._self._c || e;
                return s("div", {
                    ref: "timer",
                    staticClass: "timer"
                }, [s("svg", {
                    attrs: {
                        xmlns: "http://www.w3.org/2000/svg",
                        viewBox: "0 0 110 110"
                    }
                }, [s("path", {
                    staticClass: "duration",
                    attrs: {
                        d: t.arc(2 * Math.PI)
                    }
                }), t._v(" "), t.enabled ? s("path", {
                    staticClass: "elapsed",
                    attrs: {
                        d: t.arc(2 * Math.PI * (t.elapsed / t.duration))
                    }
                }) : t._e()]), t._v(" "), s("div", {
                    staticClass: "overlay"
                }, [s("div", {
                    staticClass: "controls"
                }, [t.isPaused ? s("button", {
                    key: "restart",
                    staticClass: "restart",
                    attrs: {
                        title: t.M.restart_timer
                    },
                    on: {
                        click: function(e) {
                            t.$emit("restart")
                        }
                    }
                }, [s("Sprite", {
                    attrs: {
                        src: "/images/restart.svg"
                    }
                })], 1) : s("button", {
                    key: "placeholder",
                    staticClass: "placeholder"
                }, [s("Sprite", {
                    attrs: {
                        src: "/images/restart.svg"
                    }
                })], 1)]), t._v(" "), s("div", {
                    staticClass: "time",
                    class: {
                        enabled: t.enabled, paused: t.isPaused
                    },
                    style: t.timeStyle
                }, [t._v(t._s(t.time))]), t._v(" "), s("div", {
                    staticClass: "controls"
                }, [t.isRunning ? s("button", {
                    key: "pause",
                    staticClass: "pause",
                    attrs: {
                        title: t.M.pause_timer
                    },
                    on: {
                        click: function(e) {
                            t.$emit("pause")
                        }
                    }
                }, [s("Sprite", {
                    attrs: {
                        src: "/images/pause.svg"
                    }
                })], 1) : t.isPaused ? s("button", {
                    key: "resume",
                    staticClass: "resume",
                    attrs: {
                        title: t.M.resume_timer
                    },
                    on: {
                        click: function(e) {
                            t.$emit("resume")
                        }
                    }
                }, [s("Sprite", {
                    attrs: {
                        src: "/images/play.svg"
                    }
                })], 1) : s("button", {
                    key: "placeholder",
                    staticClass: "placeholder"
                }, [s("Sprite", {
                    attrs: {
                        src: "/images/play.svg"
                    }
                })], 1)])])])
            },
            f = [],
            b = function() {
                var t = this,
                    e = t.$createElement,
                    s = t._self._c || e;
                return s("div")
            },
            y = [];
        const w = {};
        var k = {
                props: {
                    src: {
                        required: !0
                    }
                },
                async mounted() {
                    await this.load(this.src)
                },
                methods: {
                    async load(t) {
                        if (this.$el.childNodes.length > 0 && this.$el.removeChild(this.$el.childNodes[0]), !t) return;
                        let e = w[t];
                        if (!e) {
                            let s = await fetch(t);
                            e = await s.text(), w[t] = e
                        }
                        let {
                            rootElement: s
                        } = (new DOMParser).parseFromString(e, "image/svg+xml");
                        this.$el.appendChild(s)
                    }
                },
                watch: {
                    async src(t) {
                        await this.load(t)
                    }
                }
            },
            x = k,
            M = (s("cd60"), Object(h["a"])(x, b, y, !1, null, "7c844d74", null)),
            S = M.exports;

        function _(t, e, s, n) {
            let i = t + s * Math.cos(n),
                a = e + s * Math.sin(n);
            return [i, a]
        }

        function C(t) {
            t = Math.max(2 * Math.PI - t, .01);
            let [e, s] = _(55, 55, 50, t - Math.PI / 2), n = t > Math.PI ? 0 : 1, i = `M 55 5 A 50 50 0 ${n} 0 ${e} ${s}`;
            return t <= .01 && (i += " Z"), i
        }
        var P = {
                props: ["state", "enabled", "elapsed", "duration"],
                data() {
                    return {
                        timeStyle: {}
                    }
                },
                mounted() {
                    new ResizeObserver(t => {
                        let {
                            width: e,
                            height: s
                        } = t[0].contentRect, n = Math.floor(.25 * Math.min(e, s)), i = Math.ceil(.16 * n);
                        this.timeStyle = {
                            marginTop: `-${i}px`,
                            fontSize: `${n}px`
                        }
                    }).observe(this.$refs.timer)
                },
                computed: {
                    time() {
                        if (!this.enabled) return "––:––";
                        let t = Math.max(0, Math.ceil(this.duration - this.elapsed));
                        return Object(u["d"])(t)
                    },
                    isRunning() {
                        return this.state == l["c"].Running
                    },
                    isPaused() {
                        return this.state == l["c"].Paused
                    }
                },
                methods: {
                    arc: C
                },
                components: {
                    Sprite: S
                }
            },
            $ = P,
            E = (s("61c8"), Object(h["a"])($, g, f, !1, null, null, null)),
            O = E.exports,
            j = s("0567"),
            I = {
                mixins: [v],
                created() {
                    document.title = `${j["a"].countdown} - ${j["a"].app_name_short}`, document.addEventListener("keydown", this.onKeyDown)
                },
                beforeDestroy() {
                    document.removeEventListener("keydown", this.onKeyDown)
                },
                methods: {
                    showSettings() {
                        c["c"].once.showPage("settings")
                    },
                    showHistory() {
                        c["c"].once.showPage("history")
                    },
                    onKeyDown(t) {
                        " " == t.key && (this.state == l["c"].Running ? c["e"].once.pause() : this.state == l["c"].Paused && c["e"].once.resume())
                    },
                    onPause() {
                        c["e"].once.pause()
                    },
                    onResume() {
                        c["e"].once.resume()
                    },
                    onRestart() {
                        c["e"].once.restart()
                    }
                },
                computed: {
                    timerClass() {
                        return {
                            null: "",
                            [l["a"].Focus]: "focus",
                            [l["a"].ShortBreak]: "break",
                            [l["a"].LongBreak]: "break"
                        } [this.phase]
                    },
                    title() {
                        let t = j["a"].countdown,
                            e = "";
                        return this.checkpointStartAt && (t = {
                            null: j["a"].countdown,
                            [l["a"].Focus]: j["a"].focus,
                            [l["a"].ShortBreak]: j["a"].short_break,
                            [l["a"].LongBreak]: j["a"].long_break
                        } [this.phase], e = `[${Object(u["d"])(this.remainingSeconds)}] `), `${e}${t} - ${j["a"].app_name_short}`
                    }
                },
                watch: {
                    async state(t) {
                        if (t != l["c"].Stopped) return;
                        let e = await c["g"].once.getSettings(),
                            {
                                countdown: s
                            } = e[{
                                [l["a"].Focus]: "focus",
                                [l["a"].ShortBreak]: "shortBreak",
                                [l["a"].LongBreak]: "longBreak"
                            } [this.phase]];
                        s.autoclose && window.close()
                    },
                    title(t) {
                        document.title = t
                    }
                },
                components: {
                    Timer: O,
                    Sprite: S
                }
            },
            R = I,
            A = (s("6568"), Object(h["a"])(R, o, r, !1, null, null, null)),
            B = A.exports;
        a["a"].config.productionTip = !1, a["a"].config.devtools = !1, a["a"].mixin({
            computed: {
                M() {
                    return j["a"]
                }
            }
        }), new a["a"]({
            render: t => t(B)
        }).$mount("#app")
    }
});