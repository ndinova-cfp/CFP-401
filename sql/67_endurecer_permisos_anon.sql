-- 67 · Endurecer permisos del rol anónimo (usuario sin sesión)
-- Auditoría de seguridad (nov 2026). El RLS ya bloquea el acceso, esto es defensa en profundidad.
--
-- 1) El rol `anon` solo conserva SELECT sobre lo que el sitio público muestra:
--    trayectos, modulos y novedades (cada una con su política de RLS).
-- 2) Funciones disparadoras internas: ya no se pueden ejecutar como API sin sesión.
--    Quedan abiertas a propósito: preinscribir, trayectos_para_inscripcion,
--    inscripcion_estado, ayuda_contacto y los auxiliares que usan las políticas.
-- 3) Las políticas de EPS pasan de {public} a {authenticated}.
--
-- Reversión (si algo del sitio público dejara de verse):
--   grant select on public.<tabla> to anon;
--   grant execute on function public.<funcion>(<args>) to anon;

-- 1) Tablas
do $$
declare r record;
begin
  for r in
    select c.relname
    from pg_class c
    where c.relnamespace = 'public'::regnamespace
      and c.relkind in ('r', 'p', 'v', 'm', 'f')
      and c.relname not in ('trayectos', 'modulos', 'novedades')
  loop
    execute format('revoke all on public.%I from anon', r.relname);
  end loop;
end $$;

revoke insert, update, delete, truncate, references, trigger
  on public.trayectos, public.modulos, public.novedades from anon;
grant select on public.trayectos, public.modulos, public.novedades to anon;

revoke all on all sequences in schema public from anon;

-- Que las tablas nuevas no queden abiertas a anon por defecto
alter default privileges for role postgres in schema public revoke all on tables from anon;
alter default privileges for role postgres in schema public revoke all on sequences from anon;

-- 2) Funciones disparadoras: no son API
do $$
declare r record;
begin
  for r in
    select p.oid::regprocedure as f
    from pg_proc p
    where p.pronamespace = 'public'::regnamespace
      and p.proname in (
        'handle_new_user', 'profiles_proteger_admin', 'sincronizar_sede_trayecto',
        'propagar_cambio_sede', 'preinscripciones_avisar_drive',
        'proteger_inscripcion', 'controlar_reincorporacion'
      )
  loop
    execute format('revoke execute on function %s from public, anon', r.f);
  end loop;
end $$;

-- 3) EPS: solo usuarios con sesión (siguen exigiendo eps_puede())
alter policy eps_personal_all    on public.eps_personal    to authenticated;
alter policy eps_estudiantes_all on public.eps_estudiantes to authenticated;
alter policy eps_modulos_all     on public.eps_modulos     to authenticated;
alter policy eps_ptf_all         on public.eps_ptf         to authenticated;
alter policy eps_asistencia_all  on public.eps_asistencia  to authenticated;
